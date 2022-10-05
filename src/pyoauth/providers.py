import urllib.request

from oauth.google import GoogleOAuth
from pyoauth.common.exceptions import StateTokenMisMatchError
from pyoauth.common.messages import STATE_TOKEN_DOES_NOT_MATCH
from pyoauth.utils.oauth import generate_state_param


class Google:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

    def get_client(self):
        return GoogleOAuth(self.client_id, self.client_secret)

    def sign_in(self, redirect_uri: str, private_key: str):
        client = self.get_client()
        state_token = generate_state_param(private_key)
        return {
            "auth_url": client.sign_in(redirect_uri, state_token),
            "state": state_token,
        }

    def oauth_callback(
        self, request: urllib.request.Request, state: str, code: str, redirect_uri: str
    ):
        """
        Returns access token and refresh token
        :param request: Request
        :param state: State token stored locally or in cookies
        :param code: Authorization code received from OAuth provider
        :param redirect_uri: URI to redirect after processing request
        :return: dict: {"access_token": ACCESS_TOKEN, "refresh_token": REFRESH_TOKEN}
        """

        client = self.get_client()
        if request.cookies.get("state") != state:
            raise StateTokenMisMatchError({"StateToken": STATE_TOKEN_DOES_NOT_MATCH})
        return client.get_access_token(redirect_uri, code)

    def get_user_info(self, access_token: str) -> dict:
        """
        Returns user information like user email
        :param access_token: Access token
        :return: dict: {"user_email": USER_EMAIL,}
        """

        client = self.get_client()
        return client.get_user_info(access_token)
