import base64
import json
import urllib.error
import urllib.request

import boto3
import pytest
from botocore.exceptions import ClientError


def _basic_auth_header(username: str, password: str) -> str:
    userpass = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(userpass).decode('ascii')}"


def _http_post(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int = 30,
) -> tuple[int, dict[str, str], str]:
    req = urllib.request.Request(url, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return int(resp.status), dict(resp.headers.items()), raw
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8")
        except Exception:
            pass
        return int(e.code), dict(e.headers.items()) if e.headers else {}, raw


def _session_from_creds(creds: dict, *, region: str) -> boto3.session.Session:
    return boto3.session.Session(
        aws_access_key_id=creds["accessKeyId"],
        aws_secret_access_key=creds["secretAccessKey"],
        aws_session_token=creds["sessionToken"],
        region_name=region,
    )


def _assert_access_denied(exc: Exception) -> None:
    if isinstance(exc, ClientError):
        code = (exc.response.get("Error") or {}).get("Code") or ""
        if "AccessDenied" in code:
            return
        msg = (exc.response.get("Error") or {}).get("Message") or ""
        if "not authorized" in msg.lower() or "access denied" in msg.lower():
            return
    raise AssertionError(f"expected AccessDenied, got: {exc!r}")


def _stage_from_api_key_param_name(name: str) -> str:
    # Convention: /agent-enablement/<stackName>/<stage>/shared-api-key
    parts = [p for p in (name or "").split("/") if p]
    if len(parts) >= 4 and parts[0] == "agent-enablement":
        stage = str(parts[2] or "").strip()
        return stage or "prod"
    return "prod"


def test_runtime_creds_can_read_scoped_ssm_keys(
    system_stack_outputs,
    system_admin_session,
    system_shared_api_key,
    system_user_factory,
    system_seed_profile_factory,
):
    user = system_user_factory()
    system_seed_profile_factory(user, groups=["system-it"], credential_scope="runtime")

    runtime_region = system_admin_session.region_name or ""
    assert runtime_region

    stage = _stage_from_api_key_param_name(system_stack_outputs.api_key_parameter_name)
    shared_name = f"/agent-enablement/{stage}/shared/system-test-shared"
    agent_name = f"/agent-enablement/{stage}/agent/{user.sub}/system-test-agent"
    other_sub = f"other-sub-{user.sub[:8]}"
    other_name = f"/agent-enablement/{stage}/agent/{other_sub}/system-test-other"

    ssm_admin = system_admin_session.client("ssm")
    try:
        ssm_admin.put_parameter(
            Name=shared_name,
            Value="shared-secret",
            Type="SecureString",
            Overwrite=True,
        )
        ssm_admin.put_parameter(
            Name=agent_name,
            Value="agent-secret",
            Type="SecureString",
            Overwrite=True,
        )
        ssm_admin.put_parameter(
            Name=other_name,
            Value="other-secret",
            Type="SecureString",
            Overwrite=True,
        )

        headers = {
            "authorization": _basic_auth_header(user.username, user.password),
            "x-api-key": system_shared_api_key,
        }
        status, _resp_headers, raw = _http_post(system_stack_outputs.credentials_url, headers=headers)
        assert status == 200, raw
        payload = json.loads(raw)

        # Contract: broker returns base paths for key distribution.
        ssm_refs = payload.get("references", {}).get("ssmKeys") or {}
        assert ssm_refs.get("stage") == stage
        assert ssm_refs.get("sharedBasePath") == f"/agent-enablement/{stage}/shared/"
        assert ssm_refs.get("agentBasePathTemplate") == f"/agent-enablement/{stage}/agent/<principal.sub>/"

        runtime_sess = _session_from_creds(payload["credentials"], region=runtime_region)
        ssm = runtime_sess.client("ssm")

        out = ssm.get_parameter(Name=shared_name, WithDecryption=True)
        assert out["Parameter"]["Value"] == "shared-secret"

        out = ssm.get_parameter(Name=agent_name, WithDecryption=True)
        assert out["Parameter"]["Value"] == "agent-secret"

        with pytest.raises(Exception) as excinfo:
            ssm.get_parameter(Name=other_name, WithDecryption=True)
        _assert_access_denied(excinfo.value)
    finally:
        # Best-effort cleanup.
        for name in (shared_name, agent_name, other_name):
            try:
                ssm_admin.delete_parameter(Name=name)
            except Exception:
                pass

