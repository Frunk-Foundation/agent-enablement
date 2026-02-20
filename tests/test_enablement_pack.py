import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from enablement_pack import build_pack


def test_build_pack_creates_named_skill_folders_with_skill_md(tmp_path):
    manifest = ROOT / "enablement_pack" / "manifest.yaml"
    out = tmp_path / "dist"

    result = build_pack.build_pack(
        manifest_path=manifest,
        output_root=out,
        base_url="https://example.invalid/agent-enablement/latest",
    )

    version_dir = out / result["version"]
    skills_dir = version_dir / "skills"
    assert skills_dir.exists()

    for skill_name in result["skills"]:
        skill_folder = skills_dir / skill_name
        assert skill_folder.is_dir()
        assert (skill_folder / "SKILL.md").is_file()


def test_build_pack_contents_markdown_is_link_first(tmp_path):
    manifest = ROOT / "enablement_pack" / "manifest.yaml"
    out = tmp_path / "dist"

    result = build_pack.build_pack(
        manifest_path=manifest,
        output_root=out,
        base_url="https://example.invalid/agent-enablement/latest",
    )

    contents = (out / result["version"] / "CONTENTS.md").read_text(encoding="utf-8")
    assert "ArtifactsRootUrl: `https://example.invalid/agent-enablement/latest/artifacts/`" in contents
    assert "SkillsRootUrl: `https://example.invalid/agent-enablement/latest/skills/`" in contents
    assert "## Artifacts" in contents
    assert "## Skills" in contents


def test_build_pack_includes_provisioning_examples(tmp_path):
    manifest = ROOT / "enablement_pack" / "manifest.yaml"
    out = tmp_path / "dist"

    result = build_pack.build_pack(
        manifest_path=manifest,
        output_root=out,
        base_url="https://example.invalid/agent-enablement/latest",
    )

    skill_dir = out / result["version"] / "skills" / "provisioning-cfn-mode"
    examples_dir = skill_dir / "examples"
    assert examples_dir.is_dir()
    assert (examples_dir / "01-minimal-sqs.yaml").is_file()
    assert (examples_dir / "02-lambda-with-boundary.yaml").is_file()
    assert (examples_dir / "03-lambda-url-s3-writer.yaml").is_file()


def test_build_pack_does_not_include_enabler_source_artifact(tmp_path):
    manifest = ROOT / "enablement_pack" / "manifest.yaml"
    out = tmp_path / "dist"

    result = build_pack.build_pack(
        manifest_path=manifest,
        output_root=out,
        base_url="https://example.invalid/agent-enablement/latest",
    )

    version_dir = out / result["version"]
    assert not (version_dir / "artifacts" / "enabler").exists()
    assert "enabler-cli" not in result["artifacts"]
    assert (version_dir / "CONTENTS.md").is_file()


def test_build_pack_generates_static_bundle_zip_without_secrets(tmp_path):
    manifest = ROOT / "enablement_pack" / "manifest.yaml"
    out = tmp_path / "dist"

    result = build_pack.build_pack(
        manifest_path=manifest,
        output_root=out,
        base_url="https://example.invalid/agent-enablement/latest",
    )
    bundle_zip = Path(result["bundleZipPath"])
    assert bundle_zip.is_file()
    assert result["bundleZipSha256"]
    with zipfile.ZipFile(bundle_zip, "r") as zf:
        names = set(zf.namelist())
    assert "CONTENTS.md" in names
    assert "metadata.json" in names
    assert "credentials.json" not in names
