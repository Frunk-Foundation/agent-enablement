#!/usr/bin/env python3
"""Publish enablement pack dist to S3 and update latest pointers."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _session() -> boto3.session.Session:
    # Repo convention: account-level boto3 calls use explicit AWS_PROFILE/AWS_REGION.
    return boto3.session.Session(
        profile_name=os.environ["AWS_PROFILE"],
        region_name=os.environ["AWS_REGION"],
    )


def _parse_args() -> argparse.Namespace:
    root = _repo_root()
    parser = argparse.ArgumentParser(description="Publish enablement pack to S3")
    parser.add_argument("--bucket", required=True, help="Target S3 bucket")
    parser.add_argument("--version", required=True, help="Version folder under dist/")
    parser.add_argument(
        "--dist-root",
        default=str(root / "enablement_pack" / "dist"),
        help="Root containing dist/<version>",
    )
    parser.add_argument(
        "--prefix",
        default="agent-enablement",
        help="S3 key prefix for published bundle",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without uploading",
    )
    return parser.parse_args()


def _put_object(s3: Any, *, bucket: str, key: str, body: bytes, dry_run: bool) -> None:
    if dry_run:
        print(f"DRYRUN put s3://{bucket}/{key}")
        return
    s3.put_object(Bucket=bucket, Key=key, Body=body)


def publish_one(
    *, bucket: str, version: str, dist_root: Path, prefix: str, dry_run: bool
) -> dict[str, Any]:
    version_dir = dist_root / version
    if not version_dir.exists():
        raise FileNotFoundError(f"missing version dir: {version_dir}")
    bundle_zip_path = version_dir / "agent-enablement-bundle.zip"
    if not bundle_zip_path.exists():
        raise FileNotFoundError(
            f"missing canonical bundle zip: {bundle_zip_path} (run `enabler-admin pack-build` first)"
        )

    s3 = _session().client("s3")

    uploaded = 0
    for path in sorted(version_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(version_dir).as_posix()
        body = path.read_bytes()
        key = f"{prefix}/{version}/{rel}"
        _put_object(
            s3,
            bucket=bucket,
            key=key,
            body=body,
            dry_run=dry_run,
        )
        # Publish stable "latest/..." copies so broker-provided URLs under
        # agent-enablement/latest/... keep working without consumers needing
        # to parse latest.json to find the current version.
        _put_object(
            s3,
            bucket=bucket,
            key=f"{prefix}/latest/{rel}",
            body=body,
            dry_run=dry_run,
        )
        uploaded += 2

    bundle_body = bundle_zip_path.read_bytes()
    _put_object(
        s3,
        bucket=bucket,
        key=f"{prefix}/{version}/agent-enablement-bundle.zip",
        body=bundle_body,
        dry_run=dry_run,
    )
    _put_object(
        s3,
        bucket=bucket,
        key=f"{prefix}/latest/agent-enablement-bundle.zip",
        body=bundle_body,
        dry_run=dry_run,
    )
    uploaded += 2

    latest_doc = {
        "schemaVersion": "2026-02-14",
        "updatedAt": _utc_now(),
        "version": version,
        "contentsKey": f"{prefix}/latest/CONTENTS.md",
        "versionedContentsKey": f"{prefix}/{version}/CONTENTS.md",
        "artifactsRootKey": f"{prefix}/{version}/artifacts/",
        "skillsRootKey": f"{prefix}/{version}/skills/",
        "bundleZipKey": f"{prefix}/latest/agent-enablement-bundle.zip",
        "versionedBundleZipKey": f"{prefix}/{version}/agent-enablement-bundle.zip",
    }
    _put_object(
        s3,
        bucket=bucket,
        key=f"{prefix}/latest.json",
        body=(json.dumps(latest_doc, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        dry_run=dry_run,
    )

    bucket_host = os.environ.get("ENABLEMENT_BUCKET_HOST") or f"{bucket}.s3.{os.environ['AWS_REGION']}.amazonaws.com"
    base_url = f"https://{bucket_host}/{prefix}"

    return {
        "bucket": bucket,
        "prefix": prefix,
        "version": version,
        "uploadedFiles": uploaded,
        "contentsUrl": f"{base_url}/latest/CONTENTS.md",
        "bundleZipUrl": f"{base_url}/latest/agent-enablement-bundle.zip",
        "versionedBundleZipUrl": f"{base_url}/{version}/agent-enablement-bundle.zip",
        "artifactsRootUrl": f"{base_url}/latest/artifacts/",
        "skillsRootUrl": f"{base_url}/latest/skills/",
        "latestPointerUrl": f"{base_url}/latest.json",
        "dryRun": dry_run,
    }


def publish(
    *,
    bucket: str,
    version: str,
    dist_root: Path,
    prefix: str,
    dry_run: bool,
) -> dict[str, Any]:
    primary_prefix = (prefix or "").strip("/") or "agent-enablement"
    return publish_one(
        bucket=bucket,
        version=version,
        dist_root=dist_root,
        prefix=primary_prefix,
        dry_run=dry_run,
    )


def main() -> None:
    args = _parse_args()
    result = publish(
        bucket=args.bucket,
        version=args.version,
        dist_root=Path(args.dist_root).resolve(),
        prefix=args.prefix,
        dry_run=bool(args.dry_run),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
