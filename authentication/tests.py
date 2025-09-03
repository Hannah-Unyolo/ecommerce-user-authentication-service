from django.test import TestCase, Client
from django.urls import reverse

class Auth0IntegrationTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_login_redirects_to_auth0(self):
        response = self.client.get(reverse("login"))
        # Auth0 authorize URL contains your domain
        self.assertIn("https://", response.url)
        self.assertEqual(response.status_code, 302)

    def test_callback_sets_session(self):
        # Mock token returned from Auth0
        session_data = {"userinfo": {"sub": "auth0|123", "email": "test@example.com"}}
        session = self.client.session
        session["user"] = session_data
        session.save()

        response = self.client.get(reverse("index"))
        self.assertContains(response, "test@example.com")

    def test_logout_clears_session(self):
        session = self.client.session
        session["user"] = {"email": "test@example.com"}
        session.save()

        response = self.client.get(reverse("logout"))
        self.assertNotIn("user", self.client.session)
        self.assertEqual(response.status_code, 302)
