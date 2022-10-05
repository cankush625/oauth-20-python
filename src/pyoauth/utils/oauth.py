import base64
import datetime
import hashlib
import hmac

from pyoauth.common.exceptions import NonceExpiredError
from pyoauth.common.messages import NONCE_EXPIRED_ERROR


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
    payload = {
        "issued_at": current_timestamp,
    }
    hashed_state = hmac.new(
        private_key.encode("utf-8"), str(payload).encode("utf-8"), hashlib.sha256
    )
    return base64.b64encode(hashed_state.digest()).decode("utf-8")


def generate_nonce(expiration_time: int = 10) -> str:
    """
    expiration_time: int: Expiration time in minutes
    :return: str: nonce string
    """

    current_timestamp = datetime.datetime.now()
    nonce_expiration = (
        datetime.datetime.now() + datetime.timedelta(minutes=expiration_time)
    ).isoformat()
    payload = {
        "issued_at": current_timestamp,
        "expiry": nonce_expiration,
    }
    return base64.b64encode(str(payload).encode("utf-8")).decode("utf-8")


def verify_nonce(nonce_token: str) -> None:
    """
    Check if nonce token is valid
    :param nonce_token: Nonce tokne
    :return: boolean: True if the nonce is valid
    """

    payload: dict = dict(base64.b64decode(nonce_token))

    current_timestamp = datetime.datetime.now()

    if payload.get("expiry") < current_timestamp:
        raise NonceExpiredError(NONCE_EXPIRED_ERROR)
