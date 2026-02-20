import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from enablement_pack import publish_pack


class _FakeS3:
    def __init__(self):
        self.puts = []

    def put_object(self, *, Bucket, Key, Body):
        self.puts.append((Bucket, Key, Body))
        return {}


class _FakeSession:
    def __init__(self, s3):
        self._s3 = s3

    def client(self, name):
        assert name == "s3"
        return self._s3


def test_publish_requires_static_bundle_zip(tmp_path, monkeypatch):
    dist_root = tmp_path / "dist"
    version_dir = dist_root / "v1"
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / "CONTENTS.md").write_text("# Contents\n", encoding="utf-8")

    fake_s3 = _FakeS3()
    monkeypatch.setattr(publish_pack, "_session", lambda: _FakeSession(fake_s3))

    with pytest.raises(FileNotFoundError, match="missing canonical bundle zip"):
        publish_pack.publish_one(
            bucket="bucket-1",
            version="v1",
            dist_root=dist_root,
            prefix="agent-enablement",
            dry_run=False,
        )


def test_publish_uploads_static_bundle_zip_keys(tmp_path, monkeypatch):
    dist_root = tmp_path / "dist"
    version_dir = dist_root / "v1"
    version_dir.mkdir(parents=True, exist_ok=True)
    (version_dir / "CONTENTS.md").write_text("# Contents\n", encoding="utf-8")
    (version_dir / "metadata.json").write_text("{}\n", encoding="utf-8")
    (version_dir / "agent-enablement-bundle.zip").write_bytes(b"zip-bytes")

    fake_s3 = _FakeS3()
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setattr(publish_pack, "_session", lambda: _FakeSession(fake_s3))

    result = publish_pack.publish_one(
        bucket="bucket-1",
        version="v1",
        dist_root=dist_root,
        prefix="agent-enablement",
        dry_run=False,
    )

    keys = [k for _b, k, _body in fake_s3.puts]
    assert "agent-enablement/latest/agent-enablement-bundle.zip" in keys
    assert "agent-enablement/v1/agent-enablement-bundle.zip" in keys
    assert result["bundleZipUrl"].endswith("/agent-enablement/latest/agent-enablement-bundle.zip")
    assert result["versionedBundleZipUrl"].endswith("/agent-enablement/v1/agent-enablement-bundle.zip")

    latest_doc_put = [body for _b, key, body in fake_s3.puts if key.endswith("latest.json")][0]
    latest_doc = json.loads(latest_doc_put.decode("utf-8"))
    assert latest_doc["bundleZipKey"].endswith("/latest/agent-enablement-bundle.zip")
