import os
import sys
import types
import unittest
from unittest.mock import patch

try:
    import azure.functions
except ModuleNotFoundError:
    azure = types.ModuleType("azure")
    azure_functions = types.ModuleType("azure.functions")
    azure_identity = types.ModuleType("azure.identity")
    azure_search = types.ModuleType("azure.search")
    azure_search_documents = types.ModuleType("azure.search.documents")
    azure_storage = types.ModuleType("azure.storage")
    azure_storage_blob = types.ModuleType("azure.storage.blob")

    class FunctionApp:
        def __init__(self, **kwargs):
            pass

        def route(self, **kwargs):
            return lambda function: function

    class AuthLevel:
        ANONYMOUS = "anonymous"
        FUNCTION = "function"

    class AzurePlaceholder:
        def __init__(self, *args, **kwargs):
            pass

    azure_functions.FunctionApp = FunctionApp
    azure_functions.AuthLevel = AuthLevel
    azure_functions.HttpRequest = AzurePlaceholder
    azure_functions.HttpResponse = AzurePlaceholder
    azure_identity.DefaultAzureCredential = AzurePlaceholder
    azure_identity.ManagedIdentityCredential = AzurePlaceholder
    azure_search_documents.SearchClient = AzurePlaceholder
    azure_storage_blob.BlobServiceClient = AzurePlaceholder

    sys.modules.update({
        "azure": azure,
        "azure.functions": azure_functions,
        "azure.identity": azure_identity,
        "azure.search": azure_search,
        "azure.search.documents": azure_search_documents,
        "azure.storage": azure_storage,
        "azure.storage.blob": azure_storage_blob,
    })

try:
    import validators
except ModuleNotFoundError:
    validators = types.ModuleType("validators")
    validators.url = lambda value: bool(value)
    sys.modules["validators"] = validators

import function_app


class FakeCookie:
    def __init__(self, name):
        self.name = name


class FakeResponse:
    def __init__(self, url, text=""):
        self.url = url
        self.text = text
        self.closed = False

    def close(self):
        self.closed = True

    def raise_for_status(self):
        return None


class FakeRequestsSession:
    def __init__(self, login_succeeds=True):
        self.headers = {}
        self.cookies = []
        self.closed = False
        self.get_calls = []
        self.post_calls = []
        self.login_succeeds = login_succeeds

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return FakeResponse(url)

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        if self.login_succeeds:
            self.cookies.append(FakeCookie("wordpress_logged_in_test"))
            return FakeResponse("https://wordpress.example.com/")
        return FakeResponse(url)

    def close(self):
        self.closed = True


class WordPressAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.settings = {
            "WORDPRESS_BASE_URL": "https://wordpress.example.com",
            "WORDPRESS_USERNAME": "crawler",
            "WORDPRESS_PASSWORD": "secret",
        }

    def test_anonymous_session_does_not_attempt_login(self):
        raw_session = FakeRequestsSession()

        with patch("function_app.requests.Session", return_value=raw_session):
            with function_app.create_crawl_session("https://public.example.com") as session:
                session.get("https://public.example.com/page", timeout=15)

        self.assertEqual([], raw_session.post_calls)
        self.assertTrue(raw_session.closed)

    def test_wordpress_profile_maps_to_application_settings_and_logs_in(self):
        raw_session = FakeRequestsSession()

        with patch.dict(os.environ, self.settings, clear=False):
            with patch("function_app.requests.Session", return_value=raw_session):
                with function_app.create_crawl_session(
                    "https://wordpress.example.com/private",
                    "wordpress",
                ):
                    pass

        self.assertEqual("https://wordpress.example.com/wp-login.php", raw_session.get_calls[0][0])
        login_data = raw_session.post_calls[0][1]["data"]
        self.assertEqual("crawler", login_data["log"])
        self.assertEqual("secret", login_data["pwd"])
        self.assertTrue(raw_session.closed)

    def test_wordpress_profile_rejects_other_origins_before_login(self):
        raw_session = FakeRequestsSession()

        with patch.dict(os.environ, self.settings, clear=False):
            with patch("function_app.requests.Session", return_value=raw_session):
                with self.assertRaisesRegex(ValueError, "cannot be used"):
                    function_app.create_crawl_session(
                        "https://attacker.example.com",
                        "wordpress",
                    )

        self.assertEqual([], raw_session.get_calls)
        self.assertTrue(raw_session.closed)

    def test_authenticated_session_rejects_cross_origin_page(self):
        raw_session = FakeRequestsSession()
        session = function_app.CrawlSession(
            raw_session,
            "https://wordpress.example.com",
        )

        with self.assertRaisesRegex(ValueError, "outside"):
            session.get("https://other.example.com/private")

        self.assertEqual([], raw_session.get_calls)

    def test_failed_wordpress_login_closes_session(self):
        raw_session = FakeRequestsSession(login_succeeds=False)

        with patch.dict(os.environ, self.settings, clear=False):
            with patch("function_app.requests.Session", return_value=raw_session):
                with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                    function_app.create_crawl_session(
                        "https://wordpress.example.com/private",
                        "wordpress",
                    )

        self.assertTrue(raw_session.closed)

    def test_unknown_profile_is_rejected(self):
        raw_session = FakeRequestsSession()

        with patch("function_app.requests.Session", return_value=raw_session):
            with self.assertRaisesRegex(ValueError, "Unsupported authentication profile"):
                function_app.create_crawl_session(
                    "https://public.example.com",
                    "unknown",
                )

        self.assertTrue(raw_session.closed)


if __name__ == "__main__":
    unittest.main()
