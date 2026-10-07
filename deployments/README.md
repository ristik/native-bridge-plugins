# Deployment registry

No deployment is pinned or activated yet. Installations validate manifests
against protocol/manifest.schema.json, then recompute every identity/config/
policy/profile/runtime/trust binding specified in protocol/interop.md. Schema
validation alone is not deployment authorization. No zero/test hash is a
placeholder for a future production pin. Artifact locations are installation
metadata; offline verification reads only locally pinned artifacts.
