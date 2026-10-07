# Pinned bridge-core package

The required @unicitylabs/bridge-core@0.1.0-bridge.2 was unpublished when PR1
was built. The tarball is npm-packed from the exact upstream commit/directory
in bridge-core.provenance.json, not a floating Git branch or copied interface
fork. Its SHA-256 and npm integrity are checked by protocol CI and npm lock.
This is the explicit package-artifact exception to the no-binaries rule.

To reproduce: archive the pinned upstream packages/bridge-core directory in a
temporary directory, copy bridge-core-build.package-lock.json as package-lock.json,
then run the recorded build commands with the recorded Node/npm versions.
The tarball contains the upstream build outputs and original package manifest.
No upstream licensing uniformity is asserted; this repository's dual license
applies to new native material. Upstream notices must be retained on reuse.
