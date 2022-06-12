import base64
import datetime
import hashlib
import hmac


# The querystring parameters for Authorization
# access_type is set to offline so that we can refresh an access token
# without re-promoting the user for permissions. This is recommended
# for web applications.
# include_granted_scopes is set to true for enabling incremental authorization.
def get_query_auth(client_id: str) -> dict:
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": "",
        "scope": "email",
        "access_type": "offline",
        "include_granted_scopes": "true",
        "state": "",
    }


def get_query_access(client_id: str, client_secret: str) -> dict:
    return {
        "code": "",
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": "",
        "grant_type": "authorization_code",
    }


def generate_state_param(private_key: str) -> str:
    current_timestamp = str(datetime.datetime.now().isoformat())
    hashed_state = hmac.new(private_key.encode("utf-8"), current_timestamp.encode("utf-8"), hashlib.sha1)
    return base64.b64encode(hashed_state.digest()).decode("utf-8")
