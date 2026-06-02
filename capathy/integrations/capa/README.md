# External capa integration

This bundle is the boundary between Capathy and the external capa engine:

- `manifest.json` pins the upstream repository/commit, patch checksum, adapter checksums, and resulting integration commit.
- `patches/script-support.patch` contains only changes to existing engine files and the official rule linter.
- `overlay/capa/features/` contains Capathy's new script feature classes and Python transport/adapter. These are readable source files rather than a hidden copy of the engine.

The patch adds statement scope, matching and aggregation, script formats, feature serialization, source evidence metadata, protobuf fields, and linter support. These changes require engine integration, so simply installing an unmodified PyPI capa release is insufficient.

`python -m capathy setup` fetches the pinned upstream revision into an external cache, checks and applies the patch, copies the four adapter files, and commits the result with fixed metadata. The resulting checkout is clean and has a stable revision for the rule agent's integration lock. Repeated setup reuses only a verified checkout.

`python -m capathy setup --source /path/to/existing/capa/git/clone` can fetch from an existing local clone containing the pinned upstream commit. The source repository is not modified. `--no-install` skips Python dependency installation.

To update upstream, regenerate the focused patch against the new revision, refresh adapter checksums and the deterministic runtime revision, then run all Capathy integration tests. A patch that no longer applies must fail setup rather than silently dropping changes.

Historical plans describe development inside a capa checkout. This bundle replaces that delivery structure; the planned features and release gates remain the same.
