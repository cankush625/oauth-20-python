import json
import os
import urllib
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from pyoauth.oauth.base import OAuth
from pyoauth.utils.oauth import get_query_auth, get_query_access

_client_id = os.environ.get("GOOGLE_CLIENT_ID")
_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")

# Endpoints for Google OAuth
_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
_access_endpoint = "https://oauth2.googleapis.com/token"
_email_endpoint = "https://people.googleapis.com/v1/people/me"


class GoogleOAuth(OAuth):
    """Google OAuth"""

    def __init__(
        self,
        auth_endpoint: str,
        access_endpoint: str,
        email_endpoint: str,
        query_auth: dict,
        query_access: dict,
    ) -> None:
        super().__init__(
            auth_endpoint,
            access_endpoint,
            email_endpoint,
            query_auth,
            query_access,
        )

    def get_user_info(self, access_token: str) -> dict:
        """Get the info about the authorized user"""

        # Get the user info using the access token
        querystring = urlencode(
            {"access_token": access_token, "personFields": "emailAddresses"}
        )
        req = urllib.request.Request(self.email_endpoint + "?" + querystring)

        response = urlopen(req)
        resp_data = json.load(response)

        # Extract the user email from the user info.
        # There may be a list of emails but we will use the first email
        user_email = resp_data.get("emailAddresses")[0].get("value")
        return {
            "user_email": user_email,
        }


google_oauth: GoogleOAuth = GoogleOAuth(
    auth_endpoint=_auth_endpoint,
    access_endpoint=_access_endpoint,
    email_endpoint=_email_endpoint,
    query_auth=get_query_auth(_client_id),
    query_access=get_query_access(_client_id, _client_secret),
)
