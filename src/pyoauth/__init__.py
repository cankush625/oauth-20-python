import urllib.request

from pyoauth.common.exceptions import StateTokenDoesNotMatchError
from pyoauth.common.messages import STATE_TOKEN_DOES_NOT_MATCH
from pyoauth.oauth.google import google_oauth
from pyoauth.utils.oauth import generate_state_param


class Google:
    @staticmethod
    def sign_in(redirect_uri: str, private_key: str):
        state_token = generate_state_param(private_key)
        return {
            "auth_url": google_oauth.sign_in(redirect_uri, state_token),
            "state": state_token,
        }

    @staticmethod
    def oauth_callback(
        request: urllib.request.Request, state: str, code: str, redirect_uri: str
    ):
        """
        Returns access token and refresh token
        :param request: Request
        :param state: State token stored locally or in cookies
        :param code: Authorization code received from OAuth provider
        :param redirect_uri: URI to redirect after processing request
        :return: dict: {"access_token": ACCESS_TOKEN, "refresh_token": REFRESH_TOKEN}
        """

        if request.cookies.get("state") != state:
            raise StateTokenDoesNotMatchError(
                {"StateToken": STATE_TOKEN_DOES_NOT_MATCH}
            )
        return google_oauth.get_access_token(redirect_uri, code)

    @staticmethod
    def get_user_info(access_token: str) -> dict:
        """
        Returns user information like user email
        :param access_token: Access token
        :return: dict: {"user_email": USER_EMAIL,}
        """

        return google_oauth.get_user_info(access_token)
