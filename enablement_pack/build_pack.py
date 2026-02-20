#!/usr/bin/env python3
"""Build a lean agent enablement pack with link-first artifacts and skill folders."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# YAML is a superset of JSON. We intentionally keep manifest.yaml JSON-compatible
# to avoid adding parser dependencies.

SKILL_REQUIRED_HEADINGS = [
    "# ",
    "## Purpose",
    "## When To Use",
    "## Inputs",
    "## Workflow",
    "## Outputs",
    "## Guardrails",
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    if "version" not in data or not str(data["version"]).strip():
        raise ValueError("manifest missing version")
    if "artifacts" not in data or not isinstance(data["artifacts"], list):
        raise ValueError("manifest missing artifacts list")
    if "skills" not in data or not isinstance(data["skills"], list):
        raise ValueError("manifest missing skills list")
    return data


def _git_commit(root: Path) -> str:
    try:
        return (
            subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                text=True,
            )
            .strip()
        )
    except Exception:
        return "unknown"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_dir(path: Path) -> str:
    h = hashlib.sha256()
    files = sorted(p for p in path.rglob("*") if p.is_file())
    for p in files:
        rel = p.relative_to(path).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(_sha256_file(p).encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def _sha256_path(path: Path) -> str:
    if path.is_dir():
        return _sha256_dir(path)
    return _sha256_file(path)


def _build_bundle_zip(*, version_dir: Path, zip_path: Path) -> str:
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as zf:
        for path in sorted(p for p in version_dir.rglob("*") if p.is_file()):
            if path == zip_path:
                continue
            arcname = path.relative_to(version_dir).as_posix()
            zf.write(path, arcname=arcname)
    return _sha256_file(zip_path)


def _validate_skill_md(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"skill missing SKILL.md: {path}")
    body = path.read_text(encoding="utf-8")
    for heading in SKILL_REQUIRED_HEADINGS:
        if heading not in body:
            raise ValueError(f"skill {path} missing required heading: {heading}")


def _copy_tree(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(f"missing source path: {src}")
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return
    shutil.copytree(src, dst)


def _url_join(base_url: str, rel: str) -> str:
    base = base_url.rstrip("/")
    return f"{base}/{rel.replace(os.sep, '/')}"


def _render_contents_md(
    *,
    version: str,
    generated_at: str,
    artifacts_root_url: str,
    skills_root_url: str,
    artifact_entries: list[dict[str, Any]],
    skill_entries: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("# Agent Enablement Contents")
    lines.append("")
    lines.append(f"- Version: `{version}`")
    lines.append(f"- GeneratedAt: `{generated_at}`")
    lines.append(f"- ArtifactsRootUrl: `{artifacts_root_url}`")
    lines.append(f"- SkillsRootUrl: `{skills_root_url}`")
    lines.append("")
    lines.append("## Next Step")
    lines.append("")
    lines.append("This bundle is content-only. Request secrets and short-lived credentials from `/v1/credentials`.")
    lines.append("")
    lines.append("## Artifacts")
    lines.append("")
    for a in artifact_entries:
        lines.append(f"### {a['id']}")
        if a.get("description"):
            lines.append(f"- Description: {a['description']}")
        lines.append(f"- Path: `{a['path']}`")
        lines.append(f"- URL: {a['url']}")
        lines.append(f"- SHA256: `{a['sha256']}`")
        lines.append("")
    lines.append("## Skills")
    lines.append("")
    for s in skill_entries:
        lines.append(f"### {s['name']}")
        if s.get("description"):
            lines.append(f"- Description: {s['description']}")
        lines.append(f"- Path: `{s['path']}`")
        lines.append(f"- URL: {s['url']}")
        lines.append(f"- SKILL.md: {s['skillMdUrl']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_pack(
    manifest_path: Path,
    output_root: Path,
    base_url: str,
) -> dict[str, Any]:
    root = _repo_root()
    manifest = _load_manifest(manifest_path)
    version = str(manifest["version"]).strip()

    version_dir = output_root / version
    if version_dir.exists():
        shutil.rmtree(version_dir)

    artifacts_dir = version_dir / "artifacts"
    skills_dir = version_dir / "skills"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    skills_dir.mkdir(parents=True, exist_ok=True)

    artifact_entries: list[dict[str, Any]] = []
    for art in manifest["artifacts"]:
        art_id = str(art.get("id") or "").strip()
        if not art_id:
            raise ValueError("artifact id cannot be empty")

        description = str(art.get("description", "")).strip()
        sources = art.get("sources")
        if sources is not None:
            if not isinstance(sources, list) or not sources:
                raise ValueError(f"artifact {art_id} must define a non-empty sources list")
            target_dir_rel = str(art.get("targetDir") or "").strip().strip("/")
            if not target_dir_rel:
                raise ValueError(f"artifact {art_id} missing targetDir")

            target_dir = artifacts_dir / target_dir_rel
            target_dir.mkdir(parents=True, exist_ok=True)
            for src_entry in sources:
                if not isinstance(src_entry, dict):
                    raise ValueError(f"artifact {art_id} has invalid sources entry")
                source_rel = str(src_entry.get("source") or "").strip()
                target_rel = str(src_entry.get("target") or "").strip().lstrip("/")
                if not source_rel or not target_rel:
                    raise ValueError(
                        f"artifact {art_id} sources entries require source and target"
                    )
                source = root / source_rel
                target = target_dir / target_rel
                _copy_tree(source, target)

            artifact_path = f"artifacts/{target_dir_rel}/"
            artifact_sha = _sha256_path(target_dir)
        else:
            source_rel = str(art.get("source") or "").strip()
            target_rel = str(art.get("target") or "").strip().lstrip("/")
            if not source_rel or not target_rel:
                raise ValueError(
                    f"artifact {art_id} must define source/target or sources/targetDir"
                )
            source = root / source_rel
            target = artifacts_dir / target_rel
            _copy_tree(source, target)
            artifact_path = f"artifacts/{target_rel}"
            artifact_sha = _sha256_path(target)

        artifact_entries.append(
            {
                "id": art_id,
                "description": description,
                "path": artifact_path,
                "url": _url_join(base_url, artifact_path),
                "sha256": artifact_sha,
            }
        )

    skill_entries: list[dict[str, Any]] = []
    for skill in manifest["skills"]:
        skill_name = str(skill["name"]).strip()
        if not skill_name:
            raise ValueError("skill name cannot be empty")
        src = root / str(skill["source"])
        dst = skills_dir / skill_name

        _copy_tree(src, dst)
        _validate_skill_md(dst / "SKILL.md")

        skill_entries.append(
            {
                "name": skill_name,
                "description": str(skill.get("description", "")).strip(),
                "path": f"skills/{skill_name}/",
                "url": _url_join(base_url, f"skills/{skill_name}/"),
                "skillMdPath": f"skills/{skill_name}/SKILL.md",
                "skillMdUrl": _url_join(base_url, f"skills/{skill_name}/SKILL.md"),
            }
        )

    generated_at = _utc_now()
    artifacts_root_url = _url_join(base_url, "artifacts/")
    skills_root_url = _url_join(base_url, "skills/")
    contents_path = version_dir / "CONTENTS.md"
    contents_path.write_text(
        _render_contents_md(
            version=version,
            generated_at=generated_at,
            artifacts_root_url=artifacts_root_url,
            skills_root_url=skills_root_url,
            artifact_entries=artifact_entries,
            skill_entries=skill_entries,
        ),
        encoding="utf-8",
    )

    metadata = {
        "version": version,
        "generatedAt": _utc_now(),
        "sourceCommit": _git_commit(root),
        "manifestPath": str(manifest_path.relative_to(root)),
        "contentsSha256": _sha256_path(contents_path),
        "skills": [s["name"] for s in skill_entries],
        "artifacts": [a["id"] for a in artifact_entries],
    }
    metadata_path = version_dir / "metadata.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    bundle_zip_path = version_dir / "agent-enablement-bundle.zip"
    bundle_zip_sha256 = _build_bundle_zip(version_dir=version_dir, zip_path=bundle_zip_path)

    return {
        "version": version,
        "outputDir": str(version_dir),
        "contentsPath": str(contents_path),
        "metadataPath": str(metadata_path),
        "bundleZipPath": str(bundle_zip_path),
        "bundleZipSha256": bundle_zip_sha256,
        "skills": [s["name"] for s in skill_entries],
        "artifacts": [a["id"] for a in artifact_entries],
    }


def _parse_args() -> argparse.Namespace:
    root = _repo_root()
    parser = argparse.ArgumentParser(description="Build enablement pack dist artifacts")
    parser.add_argument(
        "--manifest",
        default=str(root / "enablement_pack" / "manifest.yaml"),
        help="Path to JSON-compatible manifest.yaml",
    )
    parser.add_argument(
        "--output-root",
        default=str(root / "enablement_pack" / "dist"),
        help="Output root where dist/<version>/ is created",
    )
    parser.add_argument(
        "--base-url",
        default="https://example.invalid/agent-enablement/latest",
        help="Base URL used to render link-first index URLs",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    result = build_pack(
        manifest_path=Path(args.manifest).resolve(),
        output_root=Path(args.output_root).resolve(),
        base_url=str(args.base_url),
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
