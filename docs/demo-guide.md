# SecureDoc Demo Guide

Use this guide for the Information Security classroom demo. The main flow is the current client-side digital signature flow with an `x509-demo` certificate. Do not use the legacy signing tab for the main demo.

## Before Demo

1. Start the backend.
2. Start the frontend.
3. Open `Documents`.
4. Use demo PIN `123456` when the UI asks for a PIN.

## Main Flow

1. Generate key in browser.
2. Request X.509 demo certificate.
3. Upload or select a document.
4. Create signing request.
5. Review `signingPayload`.
6. Enter demo PIN.
7. Sign in browser.
8. Submit `signedPackage`.
9. Inspect verification report.
10. Revoke certificate and verify again.

## Case 1: Sign Original File And Verify Successfully

1. In `Documents`, enter signer name and email.
2. Click `Generate key and request certificate`.
3. Select a document.
4. Click `Create signing request`.
5. Review `documentName`, `documentHash`, signer, certificate serial, certificate fingerprint, purpose, `requestId`, and `nonce`.
6. Enter demo PIN `123456`.
7. Click `Sign in browser and submit`.
8. Click `Verify report`.

Expected result: report has `documentIntegrity=passed`, `signatureValid=passed`, `certificateChainValid=passed`, `certificateRevocationStatus=valid`, and `finalDecision=valid`.

## Case 2: Modify File And Verify Fails

1. Download/export `signed_package_v2.json`.
2. Edit the original document locally and save it as a changed file.
3. Open `Xac minh v2`.
4. Upload the changed file and the original `signed_package_v2.json`.
5. Click `Verify v2`.

Expected result: `documentIntegrity=failed` and final decision is invalid.

## Case 3: Revoke Certificate And Verify Fails

1. Complete Case 1.
2. In `Documents`, click `Revoke certificate and verify again`.

Expected result: certificate status becomes `certificate_revoked`; report has `certificateRevocationStatus=revoked` and `revocationSource=server-db`.

## Case 4: Inspect Verification Report

Show these report fields:

- `documentIntegrity`
- `signingPayloadValid`
- `signatureValid`
- `certificateParsed`
- `certificateTrusted`
- `certificateType`
- `certificateChainValid`
- `certificateValidityPeriod`
- `keyUsageValid`
- `certificateRevocationStatus`
- `revocationSource`
- `replayCheck`
- `timestampStatus`
- `algorithmPolicyValid`
- `finalDecision`

Explain that the report is deliberately more useful than a single true/false result.

## Case 5: Check Audit Chain

1. Complete a signing or verification action.
2. In `Documents`, click `Verify audit hash chain`.

Expected result: `valid=true` and `brokenAt=null`.

## Legacy Warning

The legacy sign tab is kept only for compatibility demonstrations.

`Insecure legacy demo: backend receives privateKeyPem.`

## Blind Signature Demo

Use tab `Chu ky mu` for the privacy-token demo. This is separate from document signing.

1. Choose purpose: `anonymous_access_token`, `e_voting_demo`, or `e_cash_demo`.
2. Click `Create token and blind it`.
3. Click `Sign blinded token`.
4. Click `Unblind in browser`.
5. Click `Verify final signature`.
6. Click `Redeem token`.
7. Click `Redeem again`.

Expected result: the final signature verifies; first redeem succeeds; second redeem fails because the token is already spent.

Explain: ordinary document signatures identify a signer for a document. Blind signatures authorize an opaque token for privacy/anonymous-token scenarios.

## Production Limits

- Demo CA only.
- No public CA integration.
- No HSM, smart card, or USB token.
- Demo TSA only, not production timestamping.
- No production PAdES, XAdES, or CAdES.
- No legal validity.
- Visual stamp preview is not PAdES.
- Blind signature demo is not production e-voting or e-cash and does not replace the document signing flow.
