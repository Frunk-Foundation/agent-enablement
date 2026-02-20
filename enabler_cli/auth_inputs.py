from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence


class AuthInputError(ValueError):
    """Raised when CLI auth inputs are missing or conflicting."""


class MissingEndpointError(AuthInputError):
    """Raised when an endpoint is required but missing."""


class InvalidTokenShapeError(AuthInputError):
    """Raised when a supplied token is not in JWT shape."""


class PreflightValidationError(AuthInputError):
    """Raised when strict client-side preflight validation fails."""


@dataclass(frozen=True)
class BasicCredentials:
    username: str
    password: str


@dataclass(frozen=True)
class AgentRequestAuth:
    endpoint: str
    api_key: str


@dataclass(frozen=True)
class CognitoHttpRequestAuth:
    endpoint: str
    id_token: str


def _require_non_empty(val: str | None, *, name: str, hint: str) -> str:
    out = (val or "").strip()
    if not out:
        raise AuthInputError(f"missing {name} ({hint})")
    return out


def resolve_basic_credentials(
    *,
    username: str | None,
    password: str | None,
    env_or_none: Callable[..., str | None],
    username_env_names: Sequence[str] = ("ENABLER_COGNITO_USERNAME",),
    password_env_names: Sequence[str] = ("ENABLER_COGNITO_PASSWORD",),
) -> BasicCredentials:
    username_hint_env = str(username_env_names[0]).strip() if username_env_names else "ENABLER_COGNITO_USERNAME"
    password_hint_env = str(password_env_names[0]).strip() if password_env_names else "ENABLER_COGNITO_PASSWORD"
    resolved_username = _require_non_empty(
        username or env_or_none(*username_env_names),
        name="username",
        hint=f"--username or env {username_hint_env}",
    )
    resolved_password = _require_non_empty(
        password or env_or_none(*password_env_names),
        name="password",
        hint=f"--password or env {password_hint_env}",
    )
    return BasicCredentials(username=resolved_username, password=resolved_password)


def resolve_agent_request_auth_client(
    *,
    endpoint: str | None,
    endpoint_env_names: Sequence[str],
    api_key: str | None,
    api_key_env_names: Sequence[str],
    env_or_none: Callable[..., str | None],
    missing_endpoint_error: str,
    missing_api_key_error: str,
    derive_endpoint_from_credentials_env: Callable[[str], str] | None = None,
    credentials_endpoint_env_names: Sequence[str] = (),
) -> AgentRequestAuth:
    """Resolve client-agent endpoint/api-key without stack/SSM/account fallbacks."""

    resolved_endpoint = (endpoint or env_or_none(*endpoint_env_names) or "").strip()
    if not resolved_endpoint and derive_endpoint_from_credentials_env is not None:
        credentials_endpoint = (env_or_none(*credentials_endpoint_env_names) or "").strip()
        if credentials_endpoint:
            resolved_endpoint = (
                derive_endpoint_from_credentials_env(credentials_endpoint) or ""
            ).strip()

    resolved_api_key = (api_key or env_or_none(*api_key_env_names) or "").strip()

    if not resolved_endpoint:
        raise MissingEndpointError(missing_endpoint_error)
    if not resolved_api_key:
        raise AuthInputError(missing_api_key_error)

    return AgentRequestAuth(endpoint=resolved_endpoint, api_key=resolved_api_key)


def preflight_cognito_http_request(
    *,
    endpoint: str,
    id_token: str,
    endpoint_name: str,
    token_name: str,
    expected_base_path: str | None = None,
) -> CognitoHttpRequestAuth:
    endpoint_value = _require_non_empty(
        endpoint,
        name=endpoint_name,
        hint=f"pass --endpoint or configure stack output for {endpoint_name}",
    ).rstrip("/")

    if expected_base_path:
        marker = expected_base_path.strip()
        if marker and marker not in endpoint_value:
            raise PreflightValidationError(
                f"{endpoint_name} must include {marker!r}; got {endpoint_value!r}"
            )

    token_value = _require_non_empty(
        id_token,
        name=token_name,
        hint="pass --id-token, --creds-file/--creds-json, or --username/--password",
    )
    parts = token_value.split(".")
    if len(parts) != 3 or any(not p.strip() for p in parts):
        raise InvalidTokenShapeError(
            f"{token_name} is not a JWT (expected 3 dot-separated segments)"
        )

    return CognitoHttpRequestAuth(endpoint=endpoint_value, id_token=token_value)
