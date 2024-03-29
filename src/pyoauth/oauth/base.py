import json
import urllib
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class OAuth:
    def __init__(
        self,
        query_auth: dict,
        query_access: dict,
        auth_endpoint: str,
        access_endpoint: str,
        email_endpoint: str,
    ) -> None:
        self.auth_endpoint = auth_endpoint
        self.access_endpoint = access_endpoint
        self.email_endpoint = email_endpoint
        self.query_auth = query_auth
        self.query_access = query_access

    def sign_in(self, redirect_uri: str, state: str) -> str:
        """
        Returns the redirect endpoint having vendor-appropriate querystring
        :param redirect_uri: URI to redirect the client. Generally a callback URI
        :param state: State token for protecting from CSRF attacks
        """

        self.query_auth.update({"state": state})
        self.query_auth.update({"redirect_uri": redirect_uri})
        # encode query params
        querystring = urlencode(self.query_auth)
        return self.auth_endpoint + "?" + querystring

    def get_access_token(self, redirect_uri: str, code: str) -> dict:
        """
        Returns access token and refresh token
        :param redirect_uri: URI to redirect the client. Generally a callback URI
        :param code: authorization code
        """

        self.query_access.update({"code": code})
        self.query_access.update({"redirect_uri": redirect_uri})

        # Build the URL to call with our data
        data = bytes(urlencode(self.query_access), "utf-8")
        req = urllib.request.Request(self.access_endpoint, data)

        # Call the endpoint to get the access token and refresh token
        response = urlopen(req)
        resp_data = json.load(response)
        access_token = resp_data.get("access_token")
        refresh_token = resp_data.get("refresh_token", "")

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }
