import azure.functions as func
import hashlib
import json
import logging
import os
import re
import requests
import traceback
import validators
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote, urljoin, urlparse, urlunparse

from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.search.documents import SearchClient
from azure.storage.blob import BlobServiceClient
from bs4 import BeautifulSoup

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

CHUNK_SIZE = 2000  # characters per chunk, tuned for AI Search
DEFAULT_MAX_PAGES = int(os.environ.get("CRAWL_MAX_PAGES", "100"))
CRAWL_NESTED_SITEMAPS = os.environ.get("CRAWL_NESTED_SITEMAPS", "false").lower() == "true"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
GRAPH_REQUEST_TIMEOUT = int(os.environ.get("GRAPH_REQUEST_TIMEOUT", "10"))
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
AUTH_PROFILES = {
    "wordpress": {
        "type": "wordpress",
        "base_url_setting": "WORDPRESS_BASE_URL",
        "username_setting": "WORDPRESS_USERNAME",
        "password_setting": "WORDPRESS_PASSWORD",
    },
}


class CrawlSession:
    def __init__(self, session, authenticated_base_url=None):
        self._session = session
        self._authenticated_base_url = authenticated_base_url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback_value):
        self.close()

    def close(self):
        self._session.close()

    def get(self, url, **kwargs):
        if self._authenticated_base_url and not _same_origin(url, self._authenticated_base_url):
            raise ValueError("Authenticated crawls cannot request URLs outside the configured WordPress origin")

        response = self._session.get(url, **kwargs)

        if self._authenticated_base_url:
            if not _same_origin(response.url, self._authenticated_base_url):
                response.close()
                raise RuntimeError("An authenticated crawl was redirected outside the configured WordPress origin")
            if urlparse(response.url).path.rstrip("/").endswith("/wp-login.php"):
                response.close()
                raise RuntimeError("The WordPress session expired or the requested page requires authentication")

        return response


def _url_origin(url):
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        return None

    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, parsed.hostname.lower(), port


def _same_origin(first_url, second_url):
    first_origin = _url_origin(first_url)
    return first_origin is not None and first_origin == _url_origin(second_url)


def get_auth_profile(profile_name):
    if not profile_name:
        return None

    profile = AUTH_PROFILES.get(profile_name)
    if not profile:
        raise ValueError(f"Unsupported authentication profile: {profile_name}")

    setting_fields = {
        "base_url": profile["base_url_setting"],
        "username": profile["username_setting"],
        "password": profile["password_setting"],
    }
    resolved = {"type": profile["type"]}
    missing_settings = []

    for field, setting_name in setting_fields.items():
        value = os.environ.get(setting_name)
        if value:
            resolved[field] = value
        else:
            missing_settings.append(setting_name)

    if missing_settings:
        raise RuntimeError(
            f"Authentication profile '{profile_name}' is missing required application settings: "
            f"{', '.join(missing_settings)}"
        )

    if _url_origin(resolved["base_url"]) is None:
        raise RuntimeError(f"Authentication profile '{profile_name}' has an invalid base URL")

    return resolved


def authenticate_wordpress(session, requested_url, profile):
    base_url = profile["base_url"].rstrip("/")

    if not _same_origin(requested_url, base_url):
        raise ValueError(
            "The WordPress authentication profile cannot be used for the requested URL"
        )

    login_url = f"{base_url}/wp-login.php"

    # STEP 1: GET wp-login.php to receive cookies + hidden fields
    response = session.get(login_url, timeout=15)
    response.raise_for_status()

    from bs4 import BeautifulSoup

    soup = BeautifulSoup(response.text, "lxml")

    # Extract redirect_to hidden field (fallback to /wp-admin)
    redirect_el = soup.find("input", {"name": "redirect_to"})
    redirect_to = (
        redirect_el["value"]
        if redirect_el and redirect_el.get("value")
        else f"{base_url}/wp-admin/"
    )

    # Extract testcookie hidden field (fallback to "1")
    testcookie_el = soup.find("input", {"name": "testcookie"})
    testcookie_val = (
        testcookie_el["value"] if testcookie_el and testcookie_el.get("value") else "1"
    )

    # STEP 2: POST login form with correct hidden fields
    response = session.post(
        login_url,
        data={
            "log": profile["username"],
            "pwd": profile["password"],
            "wp-submit": "Log In",
            "redirect_to": redirect_to,
            "testcookie": testcookie_val,
        },
        timeout=15,
        allow_redirects=True,
    )
    response.raise_for_status()

    # BLOCK REDIRECT LEAVING ORIGIN
    if not _same_origin(response.url, base_url):
        response.close()
        raise RuntimeError(
            "WordPress authentication redirected outside the configured origin"
        )

    # BLOCK FAILED LOGIN (redirect back to wp-login.php)
    if urlparse(response.url).path.rstrip("/").endswith("/wp-login.php"):
        response.close()
        raise RuntimeError(
            "The WordPress session expired or the requested page requires authentication"
        )

    # VERIFY LOGIN BY COOKIE
    if not any(
        cookie.name.startswith("wordpress_logged_in_") for cookie in session.cookies
    ):
        raise RuntimeError("WordPress authentication failed")

    
#    base_url = profile["base_url"].rstrip("/")
#    if not _same_origin(requested_url, base_url):
#        raise ValueError("The WordPress authentication profile cannot be used for the requested URL")

#    login_url = f"{base_url}/wp-login.php"
#    response = session.get(login_url, timeout=15)
#    response.raise_for_status()

#    response = session.post(
#        login_url,
#        data={
#            "log": profile["username"],
#            "pwd": profile["password"],
#            "wp-submit": "Log In",
#            "redirect_to": f"{base_url}/",
#            "testcookie": "1",
#        },
#        timeout=15,
#        allow_redirects=True,
#    )
#    response.raise_for_status()

#    if not _same_origin(response.url, base_url):
#        raise RuntimeError("WordPress authentication redirected outside the configured origin")

#    if not any(cookie.name.startswith("wordpress_logged_in_") for cookie in session.cookies):
#        raise RuntimeError("WordPress authentication failed")




def create_crawl_session(url, profile_name=None):
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)

    try:
        profile = get_auth_profile(profile_name)
        if not profile:
            return CrawlSession(session)

        if profile["type"] == "wordpress":
            authenticate_wordpress(session, url, profile)
            return CrawlSession(session, profile["base_url"])

        raise ValueError(f"Unsupported authentication type: {profile['type']}")
    except Exception:
        session.close()
        raise


def _get_azure_identity_credential():
    client_id = os.environ.get("MANAGED_IDENTITY_CLIENT_ID")
    if client_id:
        return ManagedIdentityCredential(client_id=client_id)
    return DefaultAzureCredential()


def _build_graph_item_url(doc_url):
    """Return a trusted, encoded Graph drive-item URL."""
    if not isinstance(doc_url, str) or not doc_url.strip():
        return None

    doc_url = doc_url.strip()
    if doc_url.startswith("/") and not doc_url.startswith("//"):
        path = doc_url
        query = ""
    else:
        parsed = urlparse(doc_url)
        try:
            port = parsed.port
        except ValueError:
            return None
        if (
            parsed.scheme.lower() != "https"
            or parsed.hostname != "graph.microsoft.com"
            or parsed.username
            or parsed.password
            or port not in (None, 443)
        ):
            return None
        path = parsed.path
        query = parsed.query

    if path.startswith("/drives/"):
        path = f"/v1.0{path}"
    elif not path.startswith("/v1.0/drives/"):
        return None

    encoded_path = quote(path, safe="/%:!$&'()*+,;=@-._~")
    return urlunparse(("https", "graph.microsoft.com", encoded_path, "", query, ""))


def _resolve_sharepoint_url(doc_url, access_token):
    graph_url = _build_graph_item_url(doc_url)
    if not graph_url:
        logging.warning("Ignoring an invalid or untrusted doc_url: %r", doc_url)
        return None

    try:
        response = requests.get(
            graph_url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=GRAPH_REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        web_url = response.json().get("webUrl")
        if not web_url:
            logging.warning("Microsoft Graph returned no webUrl for doc_url: %s", doc_url)
            return None
        return web_url
    except requests.exceptions.RequestException as error:
        status_code = error.response.status_code if error.response is not None else None
        logging.warning(
            "Failed to resolve doc_url through Microsoft Graph (status=%s): %s",
            status_code,
            doc_url,
        )
    except (TypeError, ValueError):
        logging.warning("Microsoft Graph returned invalid JSON for doc_url: %s", doc_url)
    return None


def parse_semantic_config(raw):
    """Parse a shared or per-index semantic configuration setting."""
    mapping = {}
    if not raw:
        return mapping
    if "=" not in raw:
        mapping["*"] = raw.strip()
        return mapping
    for pair in raw.split(","):
        index_name, _, config_name = pair.partition("=")
        index_name = index_name.strip()
        config_name = config_name.strip()
        if index_name and config_name:
            mapping[index_name] = config_name
    return mapping


@app.route(route="search_site", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def search_site(req: func.HttpRequest) -> func.HttpResponse:
    logging.error('Python HTTP trigger function processed a request.')
    #logging.info('Python HTTP trigger function processed a request.')

    url = req.params.get('url')
    auth_profile = req.params.get('auth_profile')
    max_pages = None
    try:
        req_body = req.get_json()
    except ValueError:
        req_body = {}

    url = url or req_body.get('url')
    auth_profile = auth_profile or req_body.get('auth_profile')
    max_pages = req_body.get('max_pages')

    if url:
        if validators.url(url):
            try:
                with create_crawl_session(url, auth_profile) as session:
                    if _is_sitemap_candidate(url):
                        result = crawl_sitemap(url, max_pages, session)
                    else:
                        result = orchestrator_function(url, session)
            except ValueError as error:
                return func.HttpResponse(
                    json.dumps({"error": str(error)}),
                    status_code=400,
                    mimetype="application/json"
                )
            except RuntimeError as error:
                logging.error("Unable to initialize authenticated crawl: %s", error)
                return func.HttpResponse(
                    json.dumps({"error": str(error)}),
                    status_code=500,
                    mimetype="application/json"
                )
            return func.HttpResponse(
                json.dumps(result, indent=2),
                status_code=200,
                mimetype="application/json"
            )
        else:
            return func.HttpResponse(
                json.dumps({"error": "The URL was invalid."}),
                status_code=400,
                mimetype="application/json"
            )
    else:
        return func.HttpResponse(
            json.dumps({"error": "No URL was passed. Please input a URL."}),
            status_code=400,
            mimetype="application/json"
        )


@app.route(route="search_indexes", methods=["POST"], auth_level=func.AuthLevel.FUNCTION)
def search_indexes(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("search_indexes function processed a request.")

    # Validate environment configuration
    search_endpoint = os.environ.get("SEARCH_ENDPOINT")
    index_names_raw = os.environ.get("SEARCH_INDEX_NAMES")
    semantic_config_raw = os.environ.get("SEARCH_SEMANTIC_CONFIG", "default")
    semantic_config_map = parse_semantic_config(semantic_config_raw)

    if not search_endpoint or not index_names_raw:
        return func.HttpResponse(
            json.dumps({"error": "Missing required environment variables: SEARCH_ENDPOINT, SEARCH_INDEX_NAMES"}),
            status_code=400,
            mimetype="application/json"
        )

    # Parse request body
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON body."}),
            status_code=400,
            mimetype="application/json"
        )

    query = req_body.get("query")
    if not query:
        return func.HttpResponse(
            json.dumps({"error": "No 'query' field provided in request body."}),
            status_code=400,
            mimetype="application/json"
        )

    top = req_body.get("top", 5)
    index_names = [name.strip() for name in index_names_raw.split(",") if name.strip()]

    credential = _get_azure_identity_credential()
    all_results = []
    errors = []
    resolved_url_cache = {}
    graph_access_token = None
    graph_token_attempted = False

    for index_name in index_names:
        try:
            search_client = SearchClient(
                endpoint=search_endpoint,
                index_name=index_name,
                credential=credential,
            )
            semantic_config = semantic_config_map.get(index_name, semantic_config_map.get("*", "default"))
            results = search_client.search(
                search_text=query,
                query_type="semantic",
                semantic_configuration_name=semantic_config,
                top=top,
            )
            for result in results:
                source = result.get("url", "")
                doc_url = result.get("doc_url")
                if doc_url:
                    if doc_url not in resolved_url_cache:
                        if not graph_token_attempted:
                            graph_token_attempted = True
                            try:
                                graph_access_token = credential.get_token(GRAPH_SCOPE).token
                            except Exception as error:
                                logging.warning("Unable to acquire a Microsoft Graph access token: %s", error)

                        resolved_url_cache[doc_url] = (
                            _resolve_sharepoint_url(doc_url, graph_access_token)
                            if graph_access_token
                            else None
                        )
                    source = resolved_url_cache[doc_url] or source

                all_results.append({
                    "content": result.get("content") or result.get("chunk", ""),
                    "source": source,
                    "title": result.get("title", ""),
                    "index_name": index_name,
                    "score": result.get("@search.reranker_score", result.get("@search.score", 0)),
                })
        except Exception as e:
            logging.error(f"Error searching index '{index_name}': {e}")
            errors.append({"index_name": index_name, "error": str(e)})

    # Sort by score descending
    all_results.sort(key=lambda x: x["score"], reverse=True)

    return func.HttpResponse(
        json.dumps({
            "query": query,
            "total_results": len(all_results),
            "results": all_results,
            "errors": errors,
        }, indent=2),
        status_code=200,
        mimetype="application/json"
    )


def orchestrator_function(url, session=None):
    if session is None:
        with create_crawl_session(url) as anonymous_session:
            return orchestrator_function(url, anonymous_session)

    try:
        data = crawl_site(url, session)

        title = get_page_title(data)
        description = get_meta_tag(data)
        content = get_text_content(data)
        links = get_all_urls(data)

        # Split content into chunks for AI Search indexing.
        chunks = chunk_text(content, CHUNK_SIZE)

        documents = []
        for i, chunk in enumerate(chunks):
            doc_id = generate_doc_id(url, i)
            document = {
                "id": doc_id,
                "url": url,
                "title": title or "",
                "chunk_index": i,
                "total_chunks": len(chunks),
                "content": chunk,
                "metadata_description": description or "",
                "links": links,
                "crawled_at": datetime.now(timezone.utc).isoformat(),
            }
            documents.append(document)

        upload_to_blob_storage(url, documents)

        return {
            "url": url,
            "title": title,
            "total_chunks": len(chunks),
            "documents_uploaded": len(documents),
        }
    except Exception as error:
        logging.error(f"Error while crawling the site: {error}")
        logging.error(traceback.format_exc())
        return {"error": str(error)}


def _is_sitemap_candidate(url):
    """Check if the URL is a domain root or an explicit sitemap URL."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")
    return path == "" or path.endswith("/sitemap.xml") or path.endswith(".xml")


def _build_sitemap_url(url):
    """Build the sitemap URL from a domain root URL."""
    parsed = urlparse(url)
    if parsed.path.rstrip("/").endswith(".xml"):
        return url
    return urlunparse((parsed.scheme, parsed.netloc, "/sitemap.xml", "", "", ""))


def fetch_sitemap(url, session=None):
    """Fetch and parse a sitemap, returning a list of page URLs."""
    if session is None:
        with create_crawl_session(url) as anonymous_session:
            return fetch_sitemap(url, anonymous_session)

    sitemap_url = _build_sitemap_url(url)
    logging.info(f"Fetching sitemap from: {sitemap_url}")

    response = session.get(sitemap_url, allow_redirects=True, timeout=15)
    response.raise_for_status()

    root = ET.fromstring(response.content)
    # Strip XML namespace for easier tag matching
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    # Check if this is a sitemap index
    sitemap_entries = root.findall(f"{ns}sitemap")
    if sitemap_entries:
        if CRAWL_NESTED_SITEMAPS:
            logging.info(f"Sitemap index found with {len(sitemap_entries)} sub-sitemaps, following nested sitemaps.")
            urls = []
            for sitemap_el in sitemap_entries:
                loc = sitemap_el.find(f"{ns}loc")
                if loc is not None and loc.text:
                    try:
                        nested_sitemap_url = urljoin(sitemap_url, loc.text.strip())
                        urls.extend(fetch_sitemap(nested_sitemap_url, session))
                    except Exception as e:
                        logging.warning(f"Failed to fetch sub-sitemap {loc.text}: {e}")
            return urls
        else:
            logging.warning(
                f"Sitemap index found with {len(sitemap_entries)} sub-sitemaps, "
                "but CRAWL_NESTED_SITEMAPS is disabled. Skipping nested sitemaps."
            )
            return []

    # Standard sitemap with <url><loc> entries
    url_entries = root.findall(f"{ns}url")
    urls = []
    for url_el in url_entries:
        loc = url_el.find(f"{ns}loc")
        if loc is not None and loc.text:
            urls.append(urljoin(sitemap_url, loc.text.strip()))
    logging.info(f"Found {len(urls)} URLs in sitemap.")
    return urls


def crawl_sitemap(domain_url, max_pages=None, session=None):
    """Crawl all pages discovered from a sitemap."""
    if session is None:
        with create_crawl_session(domain_url) as anonymous_session:
            return crawl_sitemap(domain_url, max_pages, anonymous_session)

    if max_pages is None:
        max_pages = DEFAULT_MAX_PAGES

    try:
        page_urls = fetch_sitemap(domain_url, session)
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            logging.info("No sitemap found, falling back to single-page crawl.")
            return orchestrator_function(domain_url, session)
        raise
    except Exception as e:
        logging.warning(f"Failed to fetch sitemap: {e}. Falling back to single-page crawl.")
        return orchestrator_function(domain_url, session)

    if not page_urls:
        logging.info("Sitemap was empty or had no URLs. Falling back to single-page crawl.")
        return orchestrator_function(domain_url, session)

    total_found = len(page_urls)
    page_urls = page_urls[:max_pages]

    results = []
    errors = []
    for page_url in page_urls:
        try:
            result = orchestrator_function(page_url, session)
            if "error" in result:
                errors.append({"url": page_url, "error": result["error"]})
            else:
                results.append(result)
        except Exception as e:
            logging.error(f"Error crawling {page_url}: {e}")
            errors.append({"url": page_url, "error": str(e)})

    return {
        "sitemap_url": _build_sitemap_url(domain_url),
        "total_urls_found": total_found,
        "max_pages": max_pages,
        "pages_crawled": len(results),
        "pages_failed": len(errors),
        "results": results,
        "errors": errors,
    }


def crawl_site(url, session=None):
    if session is None:
        with create_crawl_session(url) as anonymous_session:
            return crawl_site(url, anonymous_session)

    response = session.get(url, allow_redirects=True, timeout=15)
    response.raise_for_status()
    return BeautifulSoup(response.text, "lxml")


def get_page_title(data):
    try:
        return data.title.string.strip() if data.title and data.title.string else None
    except Exception as error:
        logging.error(f"Error retrieving the site title: {error}")
        return None


def get_text_content(data):
    try:
        body = data.find("body")
        if not body:
            return ""
        for tag in body(["script", "style", "noscript", "nav", "footer", "header"]):
            tag.decompose()
        lines = (line.strip() for line in body.get_text(separator="\n").splitlines())
        return "\n".join(line for line in lines if line)
    except Exception as error:
        logging.error(f"Error retrieving text content: {error}")
        return ""


def get_all_urls(data):
    try:
        urls = []
        for el in data.select("a[href]"):
            href = el['href']
            if href.startswith("https://") or href.startswith("http://"):
                urls.append(href)
        return urls
    except Exception as error:
        logging.error(f"Error retrieving URLs: {error}")
        return []


def get_meta_tag(data):
    try:
        meta_tag = data.find("meta", attrs={'name': 'description'})
        return meta_tag["content"] if meta_tag else None
    except Exception as error:
        logging.error(f"Error retrieving meta description: {error}")
        return None


def chunk_text(text, chunk_size):
    """Split text into chunks, breaking at paragraph boundaries when possible."""
    if not text:
        return [""]

    paragraphs = text.split("\n")
    chunks = []
    current_chunk = ""

    for paragraph in paragraphs:
        if len(current_chunk) + len(paragraph) + 1 > chunk_size and current_chunk:
            chunks.append(current_chunk.strip())
            current_chunk = paragraph
        else:
            current_chunk = current_chunk + "\n" + paragraph if current_chunk else paragraph

    if current_chunk.strip():
        chunks.append(current_chunk.strip())

    return chunks if chunks else [""]


def generate_doc_id(url, chunk_index):
    """Create a deterministic, URL-safe document ID for AI Search."""
    raw = f"{url}::chunk::{chunk_index}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def upload_to_blob_storage(url, documents):
    try:
        account_url = os.environ["STORAGE_ACCOUNT_URL"]
        container_name = os.environ["STORAGE_CONTAINER_NAME"]
        credential = _get_azure_identity_credential()

        blob_service_client = BlobServiceClient(account_url, credential=credential)
        container_client = blob_service_client.get_container_client(container_name)

        if not container_client.exists():
            container_client.create_container()

        parsed = urlparse(url)
        folder = re.sub(r"[^a-zA-Z0-9_-]", "_", parsed.netloc + parsed.path)[:120]

        for doc in documents:
            blob_name = f"{folder}/{doc['id']}.json"
            blob_client = container_client.get_blob_client(blob_name)
            blob_client.upload_blob(json.dumps(doc, indent=2), overwrite=True)

        logging.info(f"Uploaded {len(documents)} documents for {url}")
    except Exception as error:
        logging.error(f"Error uploading to blob storage: {error}")
        logging.error(traceback.format_exc())
