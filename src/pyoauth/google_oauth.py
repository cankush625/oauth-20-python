import json
import os
import urllib
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from oauth import OAuth


client_id = os.environ.get("GOOGLE_CLIENT_ID")
client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")

# Endpoints for Google OAuth
_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
_access_endpoint = "https://oauth2.googleapis.com/token"
_email_endpoint = "https://people.googleapis.com/v1/people/me"

# The querystring parameters for Authorization
# access_type is set to offline so that we can refresh an access token
# without re-promoting the user for permissions. This is recommended
# for web applications.
# include_granted_scopes is set to true for enabling incremental authorization.
_query_auth = {
    "response_type": "code",
    "client_id": client_id,
    "redirect_uri": "",
    "scope": "email",
    "access_type": "offline",
    "include_granted_scopes": "true",
    "state": "",
}

_query_access = {
    "code": "",
    "client_id": client_id,
    "client_secret": client_secret,
    "redirect_uri": "",
    "grant_type": "authorization_code",
}


class GoogleOAuth(OAuth):
    """Google OAuth"""

    def __init__(
        self,
        auth_endpoint: str,
        access_endpoint: str,
        email_endpoint: str,
        query_auth: dict,
        query_access: dict,
    ):
        super().__init__(
            auth_endpoint,
            access_endpoint,
            email_endpoint,
            query_auth,
            query_access,
        )

    def get_user_info(self, access_token: str):
        """Get the info about the authorized user"""

        # Get the user info using the access token
        querystring = urlencode({"access_token": access_token, "personFields": "emailAddresses"})
        req = urllib.request.Request(self.email_endpoint + "?" + querystring)

        response = urlopen(req)
        resp_data = json.load(response)

        # Extract the user email from the user info.
        # There may be a list of emails but we will use the first email
        user_email = resp_data.get("emailAddresses")[0].get("value")
        return {
            "userEmail": user_email,
        }


google_oauth: GoogleOAuth = GoogleOAuth(
    auth_endpoint=_auth_endpoint,
    access_endpoint=_access_endpoint,
    email_endpoint=_email_endpoint,
    query_auth=_query_auth,
    query_access=_query_access,
)
