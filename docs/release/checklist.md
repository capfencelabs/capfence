# Release Checklist

Use this checklist for every CapFence release.

- Confirm version bump in `pyproject.toml` and `capfence/cli.py`.
- Update `CHANGELOG.md`.
- Run unit tests.
- Run policy fixture tests.
- Build docs.
- Build package artifacts.
- Generate an SBOM in CycloneDX or SPDX format.
- Sign the Git tag.
- Sign release artifacts or publish Sigstore attestations.
- Publish provenance attestations from CI.
- Publish to PyPI through Trusted Publishing.
- Create the GitHub release with artifacts, SBOM, signatures, and verification notes.
- Verify the PyPI package metadata points to the CapFence repository and docs.
- Document any emergency/manual release deviations.

Normal releases should use PyPI Trusted Publishing. Long-lived PyPI API tokens are reserved for emergency/manual fallback.
