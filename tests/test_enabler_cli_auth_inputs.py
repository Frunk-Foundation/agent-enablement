import pytest

from enabler_cli.auth_inputs import (
    AuthInputError,
    InvalidTokenShapeError,
    PreflightValidationError,
    preflight_cognito_http_request,
    resolve_agent_request_auth_client,
    resolve_basic_credentials,
)


def _env_lookup(env: dict[str, str]):
    def inner(*names: str):
        for n in names:
            v = (env.get(n) or "").strip()
            if v:
                return v
        return None

    return inner


def test_resolve_basic_credentials_prefers_flags_over_env():
    env_or_none = _env_lookup(
        {
            "ENABLER_COGNITO_USERNAME": "env-user",
            "ENABLER_COGNITO_PASSWORD": "env-pass",
        }
    )

    creds = resolve_basic_credentials(
        username="flag-user",
        password="flag-pass",
        env_or_none=env_or_none,
    )

    assert creds.username == "flag-user"
    assert creds.password == "flag-pass"


def test_resolve_basic_credentials_errors_when_username_missing():
    env_or_none = _env_lookup({"ENABLER_COGNITO_PASSWORD": "pw"})

    with pytest.raises(
        AuthInputError,
        match="missing username \\(--username or env ENABLER_COGNITO_USERNAME\\)",
    ):
        resolve_basic_credentials(
            username=None,
            password=None,
            env_or_none=env_or_none,
        )


def test_resolve_basic_credentials_uses_passed_admin_env_names_for_hints():
    env_or_none = _env_lookup({})
    with pytest.raises(AuthInputError, match="env ENABLER_ADMIN_COGNITO_USERNAME"):
        resolve_basic_credentials(
            username=None,
            password=None,
            env_or_none=env_or_none,
            username_env_names=("ENABLER_ADMIN_COGNITO_USERNAME",),
            password_env_names=("ENABLER_ADMIN_COGNITO_PASSWORD",),
        )


def test_resolve_agent_request_auth_client_uses_explicit_values():
    resolved = resolve_agent_request_auth_client(
        endpoint="https://example.invalid/v1/credentials",
        endpoint_env_names=("CREDENTIALS_ENDPOINT",),
        api_key="api-key",
        api_key_env_names=("API_KEY",),
        env_or_none=_env_lookup({}),
        missing_endpoint_error="missing endpoint",
        missing_api_key_error="missing key",
    )
    assert resolved.endpoint == "https://example.invalid/v1/credentials"
    assert resolved.api_key == "api-key"


def test_resolve_agent_request_auth_client_derives_endpoint_from_credentials_env():
    resolved = resolve_agent_request_auth_client(
        endpoint=None,
        endpoint_env_names=("BUNDLE_ENDPOINT",),
        api_key=None,
        api_key_env_names=("API_KEY",),
        env_or_none=_env_lookup(
            {
                "CREDENTIALS_ENDPOINT": "https://api.invalid/v1/credentials",
                "API_KEY": "env-key",
            }
        ),
        missing_endpoint_error="missing endpoint",
        missing_api_key_error="missing key",
        derive_endpoint_from_credentials_env=lambda ep: ep.replace(
            "/v1/credentials", "/v1/bundle"
        ),
        credentials_endpoint_env_names=("CREDENTIALS_ENDPOINT",),
    )
    assert resolved.endpoint == "https://api.invalid/v1/bundle"
    assert resolved.api_key == "env-key"


def test_resolve_agent_request_auth_client_raises_when_endpoint_missing():
    with pytest.raises(AuthInputError, match="missing endpoint"):
        resolve_agent_request_auth_client(
            endpoint=None,
            endpoint_env_names=("BUNDLE_ENDPOINT",),
            api_key="k",
            api_key_env_names=("API_KEY",),
            env_or_none=_env_lookup({}),
            missing_endpoint_error="missing endpoint",
            missing_api_key_error="missing key",
        )


def test_resolve_agent_request_auth_client_raises_when_api_key_missing():
    with pytest.raises(AuthInputError, match="missing key"):
        resolve_agent_request_auth_client(
            endpoint="https://api.invalid/v1/bundle",
            endpoint_env_names=("BUNDLE_ENDPOINT",),
            api_key=None,
            api_key_env_names=("API_KEY",),
            env_or_none=_env_lookup({}),
            missing_endpoint_error="missing endpoint",
            missing_api_key_error="missing key",
        )


def test_preflight_cognito_http_request_accepts_valid_endpoint_and_jwt_shape():
    out = preflight_cognito_http_request(
        endpoint="https://api.invalid/prod/v1/taskboard/",
        id_token="a.b.c",
        endpoint_name="taskboard endpoint",
        token_name="Cognito ID token",
        expected_base_path="/v1/taskboard",
    )
    assert out.endpoint == "https://api.invalid/prod/v1/taskboard"
    assert out.id_token == "a.b.c"


def test_preflight_cognito_http_request_rejects_invalid_token_shape():
    with pytest.raises(InvalidTokenShapeError, match="not a JWT"):
        preflight_cognito_http_request(
            endpoint="https://api.invalid/prod/v1/taskboard",
            id_token="not-a-jwt",
            endpoint_name="taskboard endpoint",
            token_name="Cognito ID token",
            expected_base_path="/v1/taskboard",
        )


def test_preflight_cognito_http_request_rejects_endpoint_without_expected_base_path():
    with pytest.raises(PreflightValidationError, match="/v1/taskboard"):
        preflight_cognito_http_request(
            endpoint="https://api.invalid/prod/v1/credentials",
            id_token="a.b.c",
            endpoint_name="taskboard endpoint",
            token_name="Cognito ID token",
            expected_base_path="/v1/taskboard",
        )
