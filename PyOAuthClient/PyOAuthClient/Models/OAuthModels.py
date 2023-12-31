from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class OAuthProviderMetadata(BaseModel):
    """
    The OpenID Connect Discovery response object.

    See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str  # This is actually "RECOMMENDED" but Logto requires it
    jwks_uri: str
    registration_endpoint: Optional[str] = None
    scopes_supported: List[str] = []
    response_types_supported: List[str]
    response_modes_supported: List[str] = []
    grant_types_supported: List[str] = []
    acr_values_supported: List[str] = []
    subject_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    id_token_encryption_alg_values_supported: List[str] = []
    id_token_encryption_enc_values_supported: List[str] = []
    userinfo_signing_alg_values_supported: List[str] = []
    userinfo_encryption_alg_values_supported: List[str] = []
    userinfo_encryption_enc_values_supported: List[str] = []
    request_object_signing_alg_values_supported: List[str] = []
    request_object_encryption_alg_values_supported: List[str] = []
    request_object_encryption_enc_values_supported: List[str] = []
    token_endpoint_auth_methods_supported: List[str] = []
    token_endpoint_auth_signing_alg_values_supported: List[str] = []
    display_values_supported: List[str] = []
    claim_types_supported: List[str] = []
    claims_supported: List[str] = []
    service_documentation: Optional[str] = None
    claims_locales_supported: List[str] = []
    ui_locales_supported: List[str] = []
    claims_parameter_supported: bool = False
    request_parameter_supported: bool = False
    request_uri_parameter_supported: bool = True
    require_request_uri_registration: bool = False
    op_policy_uri: Optional[str] = None
    op_tos_uri: Optional[str] = None
    end_session_endpoint: Optional[str] = None
    code_challenge_methods_supported: List[str] = []

    userlist_endpoint: str  = None# This is actually "RECOMMENDED" but Logto requires it


class Scope(Enum):
    """The scope base class for determining the scope type."""

    pass


class OAuthScope(Scope):
    offlineAccess = "offline_access"


class UserInfoScope(Scope):
    """
    The available scopes for the userinfo endpoint and the ID token claims.
    """

    openid = "openid"
    """The preserved scope for OpenID Connect. It maps to the `sub` claim."""
    profile = "profile"
    """The scope for the basic profile. It maps to the `name`, `username`, `picture` claims."""
    email = "email"
    """The scope for the email address. It maps to the `email`, `email_verified` claims."""
    phone = "phone"
    """The scope for the phone number. It maps to the `phone_number`, `phone_number_verified` claims."""
    customData = "custom_data"
    """
    The scope for the custom data. It maps to the `custom_data` claim.

    Note that the custom data is not included in the ID token by default. You need to
    use `fetchUserInfo()` to get the custom data.
    """
    identities = "identities"
    """
    The scope for the identities. It maps to the `identities` claim.

    Note that the identities are not included in the ID token by default. You need to
    use `fetchUserInfo()` to get the identities.
    """


class IdTokenClaims(BaseModel):
    """
    The ID token claims object.

    To access the extra claims, use `__pydantic_extra__`. See
    https://docs.pydantic.dev/latest/usage/models/#extra-fields for more information.
    """

    model_config = ConfigDict(extra="allow")

    iss: Optional[str] = None
    """The issuer identifier for whom issued the token."""
    sub: Optional[str] = None
    """The subject identifier for whom the token is intended (user ID)."""
    aud: Optional[str] = None
    """
    The audience that the token is intended for, which is the client ID.
    """
    exp: Optional[int] = None
    """The expiration time of the token (in seconds)."""
    iat: Optional[int] = None
    """The time at which the token was issued (in seconds)."""
    at_hash: Optional[str] = None
    name: Optional[str] = None
    """The user's full name."""
    username: Optional[str] = None
    """The user's username."""
    picture: Optional[str] = None
    """The user's profile picture URL."""
    email: Optional[str] = None
    """The user's email address."""
    email_verified: Optional[bool] = None
    """Whether the user's email address is verified."""
    phone_number: Optional[str] = None
    """The user's phone number."""
    phone_number_verified: Optional[bool] = None
    """Whether the user's phone number is verified."""


class AccessTokenClaims(BaseModel):
    """
    The access token claims object.

    To access the extra claims, use `__pydantic_extra__`. See
    https://docs.pydantic.dev/latest/usage/models/#extra-fields for more information.
    """

    model_config = ConfigDict(extra="allow")

    iss: Optional[str] = None
    """
    The issuer identifier for whom issued the token.
    """
    sub: Optional[str] = None
    """
    The subject identifier for whom the token is intended (user ID).
    """
    aud: Optional[str] = None
    """
    The audience that the token is intended for, which is the client ID or the resource
    indicator.
    """
    exp: Optional[int] = None
    """
    The expiration time of the token (in seconds).
    """
    iat: Optional[int] = None
    """
    The time at which the token was issued (in seconds).
    """
    scope: Optional[str] = None
    """
    The scopes that the token is granted for.
    """
    client_id: Optional[str] = None
    """
    The client ID that the token is granted for. Useful when the client ID is not
    included in the `aud` claim.
    """
