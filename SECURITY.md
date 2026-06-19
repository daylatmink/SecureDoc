# SecureDoc Security Policy

SecureDoc is an educational digital-signature demo. It is not production-ready,
legally-ready, RFC 3161-compliant, or PAdES-compliant.

## Supported Mode

The default mode disables legacy private-key API flows:

- `ENABLE_LEGACY_DEMO=false`
- `/api/keys/generate` is hidden from OpenAPI and returns no private key.
- `/api/sign` is hidden from OpenAPI and does not accept `privateKeyPem`.
- `ENABLE_BLIND_SIGNATURE_DEMO=false`

Only enable legacy mode for an explicit classroom compatibility demo.

Sensitive endpoints use demo RBAC headers:

- `X-SecureDoc-User`
- `X-SecureDoc-Role`

Supported demo roles are `ADMIN`, `CA_OFFICER`, `SIGNER`, `VERIFIER`, and
`AUDITOR`. This is not a production identity provider.

## Key Handling

- Do not commit private keys, `.env`, local databases, signed packages, or runtime certificates.
- Demo CA/TSA/blind-signature keys are written to `.securedoc-runtime/` by default.
- Production use requires HSM/KMS/token-backed key custody or an equivalent remote signing service.
- Signer private keys must remain with the signer or signer device.

## Reporting

For a classroom/local project, report vulnerabilities through the project owner
or course maintainer. Include the affected endpoint, reproduction steps, and
whether private keys, certificates, documents, or audit data are exposed.

## Current Limits

- Local demo CA only; no public trust store.
- Demo JSON timestamp only; no RFC 3161 `TimeStampToken`.
- No PAdES/CAdES/XAdES signing profile.
- Demo RBAC, CORS allowlist, request size limit, and in-memory rate limit only.
- No production authentication, session security, or HTTPS hardening.
- `legalReady` remains `false` by design.
