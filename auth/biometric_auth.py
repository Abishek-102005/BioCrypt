"""
BioCrypt — WebAuthn / FIDO2 Biometric Authentication
"""
import json
from flask import session, current_app
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2 import cbor

import db.models as db_models
import db.webauthn as db_webauthn
from config import RP_ID, RP_NAME

# Initialize the FIDO2 server (singleton)
_rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
_server = Fido2Server(rp=_rp)

def _get_user(user_id: int):
    """Return a UserEntity compatible with fido2 server."""
    user = db_models.get_user_by_id(user_id)
    if not user:
        raise ValueError("User not found")
    return PublicKeyCredentialUserEntity(
        id=str(user["id"]).encode(),
        name=user["username"],
        display_name=user["username"],
    )

def is_available(user_id: int = None) -> bool:
    """Return True if the given user has at least one registered credential.
    If user_id is None, check the currently logged‑in session user.
    """
    if user_id is None:
        user_id = session.get("user_id")
    if not user_id:
        return False
    creds = db_webauthn.get_webauthn_credentials_by_user(user_id)
    return len(creds) > 0

def unavailable_reason() -> str:
    return (
        "Biometric authentication requires a FIDO2‑capable authenticator (Windows Hello, "
        "Touch ID, or a hardware security key) and a configured WebAuthn relying‑party. "
        "Install `fido2` and ensure RP_ID / RP_NAME are set in config.py."
    )
# ---------------------------------------------------------------------------
# Registration flow
# ---------------------------------------------------------------------------
def begin_registration(user_id: int, username: str) -> dict:
    """Generate registration (credential creation) options for the client.
    Stores the challenge in the Flask session for later verification.
    """
    user = _get_user(user_id)
    options, state = _server.register_begin(
        user,
        user_verification="preferred",
        authenticator_selection={"authenticatorAttachment": "platform"},
    )
    session["registration_state"] = state
    return options

def complete_registration(user_id: int, credential_data: dict) -> bool:
    """Verify the registration response from the client and store the credential.
    `credential_data` is the JSON payload sent by the browser after `navigator.credentials.create`.
    """
    state = session.pop("registration_state", None)
    if not state:
        raise ValueError("No registration state found in session")
    credential = cbor.decode(credential_data)
    auth_data = _server.register_complete(state, credential)
    db_webauthn.add_webauthn_credential(
        user_id=user_id,
        credential_id=auth_data.credential_id,
        public_key=auth_data.public_key,
        sign_count=auth_data.sign_count,
        transports="",
    )
    return True
# ---------------------------------------------------------------------------
# Authentication flow
# ---------------------------------------------------------------------------
def begin_authentication(user_id: int) -> dict:
    """Generate authentication (assertion) options for the client.
    Stores the challenge in the session.
    """
    creds = db_webauthn.get_webauthn_credentials_by_user(user_id)
    if not creds:
        raise ValueError("No credentials registered for user")
    credential_ids = [c["credential_id"] for c in creds]
    options, state = _server.authenticate_begin(
        credential_ids,
        user_verification="preferred",
    )
    session["authentication_state"] = state
    return options

def complete_authentication(user_id: int, assertion_data: dict) -> bool:
    """Verify the authentication assertion from the client.
    Updates the stored sign count on success.
    """
    state = session.pop("authentication_state", None)
    if not state:
        raise ValueError("No authentication state found in session")
    assertion = cbor.decode(assertion_data)
    cred = db_webauthn.get_webauthn_credential_by_id(assertion["credentialId"])
    if not cred:
        raise ValueError("Credential not found")
    auth_data = _server.authenticate_complete(
        state,
        credential_id=assertion["credentialId"],
        client_data=assertion["clientDataJSON"],
        authenticator_data=assertion["authenticatorData"],
        signature=assertion["signature"],
        credential_public_key=cred["public_key"],
    )
    db_webauthn.update_webauthn_sign_count(
        credential_id=assertion["credentialId"],
        new_sign_count=auth_data.new_sign_count,
    )
    return True
