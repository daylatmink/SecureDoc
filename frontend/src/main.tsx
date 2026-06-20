import React, { useId, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  AlertTriangle,
  BadgeCheck,
  Ban,
  CheckCircle2,
  ClipboardCheck,
  Download,
  Eye,
  EyeOff,
  FileCheck,
  FileSignature,
  FileText,
  Fingerprint,
  Hash,
  KeyRound,
  Mail,
  RotateCcw,
  ShieldCheck,
  Smartphone,
  Upload
} from "lucide-react";
import {
  browserSigningHashSupported,
  canonicalizePayload,
  confirmSigningRequest,
  demoLogin,
  generateBrowserSigningKeyPair,
  hashDocument,
  importPrivateKey,
  issueX509Certificate,
  prepareSigningRequest,
  requestSigningEmailOtp,
  revokeCertificate,
  signPayload,
  setupTotp,
  submitSignature,
  verifyAuditChain,
  verifyTotpSetup,
  verifyV2,
  type AuditChainResult,
  type Certificate,
  type HashAlgorithm,
  type PrepareResponse,
  type SignedPackageV2,
  type SigningConfirmResponse,
  type SigningOtpRequestResponse,
  type SubmitResponse,
  type TotpSetupResponse,
  type TotpVerifyResponse,
  type VerificationReport,
  type VerificationStep,
  type VerifyV2Response,
  type X509IssueResponse
} from "./signing-v2";
import "./styles.css";

const API_BASE = "http://127.0.0.1:8000";

type LegacySignedPackage = {
  documentName: string;
  documentHash: string;
  hashAlgorithm: HashAlgorithm;
  signatureAlgorithm: string;
  signatureBase64: string;
  signedAt: string;
  certificate: Certificate;
};

type HashResult = {
  documentName: string;
  hashAlgorithm: HashAlgorithm;
  documentHash: string;
};

type VerifyDetails = Record<string, unknown> & {
  verificationSteps?: VerificationStep[];
};

type LegacyVerifyResult = {
  valid: boolean;
  reason: string;
  signer: { name: string; email: string; serialNumber: string } | null;
  documentHash: string;
  signedAt: string | null;
  details: VerifyDetails;
};

type BlindPurpose = "anonymous_access_token" | "e_voting_demo" | "e_cash_demo";

type BlindToken = {
  tokenId: string;
  purpose: BlindPurpose;
  createdAt: string;
  expiresAt: string;
  nonce: string;
  tokenVersion: string;
};

type BlindSessionResponse = {
  sessionId: string;
  tokenId: string;
  purpose: BlindPurpose;
  token: BlindToken;
  tokenHash: string;
  blindedMessageBase64: string;
  blindingFactorBase64?: string;
  blindSignatureBase64?: string | null;
  finalSignatureBase64?: string | null;
  status: string;
  createdAt: string;
  expiresAt: string;
  scheme: string;
  publicKey: { modulusBase64: string; publicExponent: number };
  warnings: string[];
  demoWarning?: string;
};

type BlindSignResponse = {
  sessionId: string;
  blindSignatureBase64: string;
  scheme: string;
  warning: string;
};

type BlindVerifyResponse = {
  valid: boolean;
  reason: string;
  sessionId: string;
  tokenId: string;
  purpose?: BlindPurpose;
};

type BlindRedeemResponse = {
  redeemed: boolean;
  reason: string;
  sessionId: string;
  tokenId: string;
  status: string;
  spentAt?: string;
};

type Tab = "home" | "documents" | "mfa" | "hash" | "keys" | "signv2" | "verifyv2" | "sign" | "verify" | "revoke" | "blind";

const tabs: Array<{ tab: Tab; label: string; helper: string; icon: React.ReactNode }> = [
  { tab: "home", label: "Tong quan", helper: "V2 flow", icon: <BadgeCheck size={18} /> },
  { tab: "documents", label: "Documents", helper: "Main flow", icon: <FileText size={18} /> },
  { tab: "mfa", label: "Security", helper: "TOTP", icon: <Smartphone size={18} /> },
  { tab: "hash", label: "Bam file", helper: "SHA-2/SHA-3", icon: <Hash size={18} /> },
  { tab: "keys", label: "Tao khoa", helper: "X.509 demo", icon: <KeyRound size={18} /> },
  { tab: "signv2", label: "Ky v2", helper: "Client-side", icon: <FileSignature size={18} /> },
  { tab: "verifyv2", label: "Xac minh v2", helper: "Report", icon: <ClipboardCheck size={18} /> },
  { tab: "revoke", label: "Thu hoi", helper: "By serial", icon: <RotateCcw size={18} /> }
];

const hashAlgorithmOptions: Array<{ value: HashAlgorithm; label: string; helper: string }> = [
  { value: "SHA-256", label: "SHA-256", helper: "Default for v2 browser signing." },
  { value: "SHA-384", label: "SHA-384", helper: "Stronger SHA-2 profile." },
  { value: "SHA-512", label: "SHA-512", helper: "512-bit SHA-2 digest." },
  { value: "SHA3-256", label: "SHA3-256", helper: "Backend supports it; browser Web Crypto cannot sign RSA-PSS with SHA3." }
];

const signingPurposes = [
  { value: "approve_document", label: "Approve document" },
  { value: "confirm_reading", label: "Confirm reading" },
  { value: "sign_contract", label: "Sign contract" },
  { value: "certify_copy", label: "Certify copy" },
  { value: "acknowledge_receipt", label: "Acknowledge receipt" }
];

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("home");

  return (
    <div className="appShell">
      <aside className="sidebar" aria-label="SecureDoc navigation">
        <div className="brand">
          <div className="brandMark" aria-hidden="true">
            <Fingerprint size={26} />
          </div>
          <div>
            <h1>SecureDoc</h1>
            <span>Digital signature demo</span>
          </div>
        </div>
        <nav className="navList">
          {tabs.map((item) => (
            <TabButton key={item.tab} {...item} active={activeTab} setActive={setActiveTab} />
          ))}
        </nav>
        <div className="sidebarNote">
          <ShieldCheck size={18} />
          <p>Main flow is Documents: browser key generation, x509-demo certificate, payload review, browser signing, verify report, and revocation demo.</p>
        </div>
      </aside>

      <main>
        {activeTab === "home" && <Home setActiveTab={setActiveTab} />}
        {activeTab === "documents" && <DocumentsWorkflow />}
        {activeTab === "mfa" && <MfaOtpSetup />}
        {activeTab === "hash" && <HashDocument />}
        {activeTab === "keys" && <GenerateKeys />}
        {activeTab === "signv2" && <SignDocumentV2 />}
        {activeTab === "verifyv2" && <VerifyDocumentV2 />}
        {activeTab === "revoke" && <RevokeCertificate />}
        {activeTab === "sign" && <SignDocumentLegacy />}
        {activeTab === "verify" && <VerifyDocumentLegacy />}
        {activeTab === "blind" && <BlindSignatureDemo />}
      </main>
    </div>
  );
}

function TabButton(props: {
  icon: React.ReactNode;
  label: string;
  helper: string;
  tab: Tab;
  active: Tab;
  setActive: (tab: Tab) => void;
}) {
  const isActive = props.active === props.tab;

  return (
    <button className={isActive ? "navButton active" : "navButton"} onClick={() => props.setActive(props.tab)} aria-current={isActive ? "page" : undefined}>
      {props.icon}
      <span>
        <strong>{props.label}</strong>
        <small>{props.helper}</small>
      </span>
    </button>
  );
}

function Home({ setActiveTab }: { setActiveTab: (tab: Tab) => void }) {
  return (
    <section className="page">
      <div className="heroPanel">
        <div className="pageHeader">
          <p className="eyebrow">Digital signature protocol</p>
          <h2>SecureDoc v2 signs canonical payloads in the browser</h2>
          <p>
            The main flow no longer sends a private key to the API. SecureDoc creates a signing payload,
            the client signs that canonical JSON, and the server verifies X.509 demo certificate trust,
            revocation, replay status, algorithm policy, document integrity, and the RSA-PSS signature.
          </p>
        </div>
        <div className="heroActions">
          <button className="primary heroAction" onClick={() => setActiveTab("keys")}>
            <KeyRound size={18} />
            Create keys
          </button>
          <button className="secondary heroAction" onClick={() => setActiveTab("documents")}>
            <ClipboardCheck size={18} />
            Open Documents
          </button>
        </div>
      </div>

      <div className="workflowGrid" aria-label="V2 workflow">
        <StepCard number="01" title="Key and certificate" text="Generate the RSA key in the browser, then request an x509-demo certificate from Demo Root CA -> Demo Intermediate CA." />
        <StepCard number="02" title="Review payload" text="Upload a document, create the signing request, inspect every signingPayload field, then confirm the signing intent." />
        <StepCard number="03" title="Verify and revoke" text="Submit the signedPackage, inspect the report, revoke the certificate, then verify again to show failure." />
      </div>

      <div className="metricGrid">
        <InfoBox title="No server-side private key" text="The v2 signing endpoint receives only a signed package, never a private key." />
        <InfoBox title="Canonical JSON" text="The signature covers the full signingPayload, not only a detached document hash." />
        <InfoBox title="DB revocation" text="Revocation is checked by serialNumber from the server DB, not from package status." />
        <InfoBox title="Demo boundaries" text="The CA chain is local demo trust only; no public CA, HSM, TSA, or PAdES profile is implemented." />
      </div>
    </section>
  );
}

function StepCard({ number, title, text }: { number: string; title: string; text: string }) {
  return (
    <article className="stepCard">
      <span>{number}</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </article>
  );
}

function InfoBox({ title, text }: { title: string; text: string }) {
  return (
    <article className="infoBox">
      <h3>{title}</h3>
      <p>{text}</p>
    </article>
  );
}

function MfaOtpSetup() {
  const [email, setEmail] = useState("student@example.com");
  const [totpSetupResult, setTotpSetupResult] = useState<TotpSetupResponse | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [totpVerify, setTotpVerify] = useState<TotpVerifyResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function setupAuthenticator() {
    setError("");
    setTotpVerify(null);
    setLoading(true);
    try {
      const response = await setupTotp({ email });
      setTotpSetupResult(response);
    } catch (err) {
      setError(errorMessage(err, "Cannot start TOTP setup."));
    } finally {
      setLoading(false);
    }
  }

  async function verifyAuthenticator() {
    if (!totpSetupResult) return;
    setError("");
    setLoading(true);
    try {
      const response = await verifyTotpSetup({
        email,
        code: totpCode
      });
      setTotpVerify(response);
    } catch (err) {
      setError(errorMessage(err, "Cannot verify TOTP setup."));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader
        title="Security settings"
        description="Set up Authenticator-based TOTP for step-up confirmation in the signing flow."
      />

      <div className="toolGrid">
        <div className="surface">
          <h3>TOTP Authenticator</h3>
          <p className="fieldHint">Use the signer email, then add the secret or otpauth URI to an Authenticator app.</p>
          <label>
            Signer email
            <input value={email} onChange={(event) => setEmail(event.target.value)} />
          </label>
          <button className="primary" onClick={setupAuthenticator} disabled={loading}>
            <Smartphone size={18} />
            Start TOTP setup
          </button>

          {totpSetupResult && (
            <dl className="detailList">
              <DetailItem label="MFA ID" value={String(totpSetupResult.mfaId)} />
              <DetailItem label="Secret" value={totpSetupResult.secret} />
              <DetailItem label="otpauth URI" value={totpSetupResult.otpauthUri} />
              <DetailItem label="Warning" value={totpSetupResult.warning} />
            </dl>
          )}

          <label>
            TOTP code
            <input value={totpCode} onChange={(event) => setTotpCode(event.target.value)} inputMode="numeric" placeholder="6 digits from Authenticator" />
          </label>
          <button className="secondary" onClick={verifyAuthenticator} disabled={loading || !totpSetupResult}>
            Verify TOTP setup
          </button>
          {totpVerify && <StatusLine ok={totpVerify.verified} text={totpVerify.reason} />}
        </div>
      </div>

      {error && <p className="errorText" role="alert">{error}</p>}
    </section>
  );
}

function StatusLine({ ok, text }: { ok: boolean; text: string }) {
  return <p className={ok ? "successText" : "errorText"}>{text}</p>;
}

type DocumentStatus = "draft" | "pending_signature" | "signed" | "verification_failed" | "certificate_revoked";
type SigningConfirmationMethod = "EMAIL_OTP" | "TOTP";

function DocumentsWorkflow() {
  const [name, setName] = useState("Nguyen Van A");
  const [email, setEmail] = useState("student@example.com");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [certificate, setCertificate] = useState<Certificate | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [purpose, setPurpose] = useState("approve_document");
  const [hashResult, setHashResult] = useState<HashResult | null>(null);
  const [prepareResult, setPrepareResult] = useState<PrepareResponse | null>(null);
  const [signingConfirmed, setSigningConfirmed] = useState(false);
  const [confirmationMethod, setConfirmationMethod] = useState<SigningConfirmationMethod>("EMAIL_OTP");
  const [confirmationCode, setConfirmationCode] = useState("");
  const [otpRequest, setOtpRequest] = useState<SigningOtpRequestResponse | null>(null);
  const [confirmationResult, setConfirmationResult] = useState<SigningConfirmResponse | null>(null);
  const [submitResult, setSubmitResult] = useState<SubmitResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyV2Response | null>(null);
  const [revokeResult, setRevokeResult] = useState<{ serialNumber: string; status: string; reason: string; revokedAt: string } | null>(null);
  const [auditResult, setAuditResult] = useState<AuditChainResult | null>(null);
  const [status, setStatus] = useState<DocumentStatus>("draft");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const signer = certificate ? `${certificate.ownerName} (${certificate.email})` : "-";
  const purposeLabel = signingPurposes.find((item) => item.value === purpose)?.label ?? purpose;

  async function createCertificate() {
    setError("");
    setLoading(true);
    try {
      await demoLogin(email, "SIGNER");
      const keyPair = await generateBrowserSigningKeyPair();
      const issued = await issueX509Certificate({ name, email, publicKeyPem: keyPair.publicKeyPem });
      setPrivateKeyPem(keyPair.privateKeyPem);
      setCertificate(issued.certificate);
      setStatus("draft");
      setPrepareResult(null);
      setSubmitResult(null);
      setVerifyResult(null);
      setRevokeResult(null);
      setSigningConfirmed(false);
      setConfirmationCode("");
      setOtpRequest(null);
      setConfirmationResult(null);
    } catch (err) {
      setError(errorMessage(err, "Cannot create browser key and X.509 demo certificate."));
    } finally {
      setLoading(false);
    }
  }

  async function createSigningRequest() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    if (!certificate) {
      setError("Generate an X.509 demo certificate first.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      await demoLogin(certificate.email, "SIGNER");
      const hash = await hashDocument(file, hashAlgorithm);
      const prepared = await prepareSigningRequest({
        documentName: file.name,
        documentHash: hash.documentHash,
        hashAlgorithm: hash.hashAlgorithm,
        certificateSerialNumber: certificate.serialNumber,
        signingPurpose: purpose,
        signerEmail: certificate.email
      });
      setHashResult(hash);
      setPrepareResult(prepared);
      setSubmitResult(null);
      setVerifyResult(null);
      setSigningConfirmed(false);
      setConfirmationCode("");
      setOtpRequest(null);
      setConfirmationResult(null);
      setStatus("pending_signature");
    } catch (err) {
      setError(errorMessage(err, "Cannot create signing request."));
    } finally {
      setLoading(false);
    }
  }

  async function requestSigningOtp() {
    if (!prepareResult) return;
    setError("");
    setLoading(true);
    try {
      const response = await requestSigningEmailOtp(prepareResult.requestId, prepareResult.signingPayload.signerEmail);
      setOtpRequest(response);
    } catch (err) {
      setError(errorMessage(err, "Cannot request signing OTP."));
    } finally {
      setLoading(false);
    }
  }

  async function confirmSigningIntent() {
    if (!prepareResult) return;
    setError("");
    setLoading(true);
    try {
      const response = await confirmSigningRequest({
        requestId: prepareResult.requestId,
        signerEmail: prepareResult.signingPayload.signerEmail,
        method: confirmationMethod,
        code: confirmationCode
      });
      setConfirmationResult(response);
      setSigningConfirmed(response.confirmed);
    } catch (err) {
      setSigningConfirmed(false);
      setError(errorMessage(err, "Cannot confirm signing request."));
    } finally {
      setLoading(false);
    }
  }

  async function signAndSubmit() {
    if (!prepareResult || !certificate) return;
    if (!signingConfirmed) {
      setError("Confirm the signing payload before signing.");
      return;
    }
    if (!privateKeyPem.trim()) {
      setError("Private key PEM is missing. Generate the key pair in this browser again.");
      return;
    }
    if (!certificate.userCertificatePem || !certificate.intermediateCertificatePem || !certificate.rootCertificatePem) {
      setError("X.509 demo certificate is missing PEM chain fields.");
      return;
    }
    const signingHash = prepareResult.signingPayload.hashAlgorithm;
    if (!browserSigningHashSupported(signingHash)) {
      setError("Browser Web Crypto cannot RSA-PSS sign with SHA3-256.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      const canonicalPayload = canonicalizePayload(prepareResult.signingPayload);
      const key = await importPrivateKey(privateKeyPem, signingHash);
      const signatureBase64 = await signPayload(key, canonicalPayload, signingHash);
      const signedPackage: SignedPackageV2 = {
        packageVersion: "2.0",
        signingPayload: prepareResult.signingPayload,
        payloadCanonicalization: "JSON-canonical-sorted-keys",
        signatureAlgorithm: "RSA-PSS",
        signatureBase64,
        userCertificatePem: certificate.userCertificatePem,
        intermediateCertificatePem: certificate.intermediateCertificatePem,
        rootCertificatePem: certificate.rootCertificatePem,
        trustedRootId: "securedoc-demo-root",
        signerCertificate: certificate,
        signedAtClient: new Date().toISOString()
      };
      const submitted = await submitSignature(signedPackage);
      setSubmitResult(submitted);
      setVerifyResult(null);
      setStatus("signed");
    } catch (err) {
      setStatus("verification_failed");
      setError(errorMessage(err, "Cannot sign or submit signedPackage."));
    } finally {
      setLoading(false);
    }
  }

  async function verifyCurrentPackage() {
    if (!file || !submitResult) {
      setError("Sign a package first.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const algorithm = submitResult.signedPackage.signingPayload.hashAlgorithm;
      const hash = await hashDocument(file, algorithm);
      const result = await verifyV2({
        documentHash: hash.documentHash,
        hashAlgorithm: hash.hashAlgorithm,
        signedPackage: submitResult.signedPackage
      });
      setVerifyResult(result);
      setStatus(result.valid ? "signed" : "verification_failed");
    } catch (err) {
      setStatus("verification_failed");
      setError(errorMessage(err, "Cannot verify signedPackage."));
    } finally {
      setLoading(false);
    }
  }

  async function revokeAndVerifyAgain() {
    if (!certificate || !file || !submitResult) {
      setError("Sign a package with an X.509 demo certificate first.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const revoked = await revokeCertificate({
        serialNumber: certificate.serialNumber,
        reason: "classroom_demo_revoke",
        revokedBy: "local-demo-user",
      });
      setRevokeResult(revoked);

      const algorithm = submitResult.signedPackage.signingPayload.hashAlgorithm;
      const hash = await hashDocument(file, algorithm);
      const result = await verifyV2({
        documentHash: hash.documentHash,
        hashAlgorithm: hash.hashAlgorithm,
        signedPackage: submitResult.signedPackage
      });
      setVerifyResult(result);
      setStatus(result.valid ? "signed" : "certificate_revoked");
    } catch (err) {
      setError(errorMessage(err, "Cannot revoke certificate or verify again."));
    } finally {
      setLoading(false);
    }
  }

  async function checkAuditChain() {
    setError("");
    try {
      setAuditResult(await verifyAuditChain());
    } catch (err) {
      setError(errorMessage(err, "Cannot verify audit chain."));
    }
  }

  return (
    <section className="page documentsPage">
      <PageHeader title="Documents workflow" description="Main digital-signature demo flow: browser key, X.509 demo certificate, signing request, signing confirmation, browser signing, verification report, revocation, and audit chain." />

      <div className="flowStrip" aria-label="Main demo flow">
        {[
          "Generate key in browser",
          "Request X.509 demo certificate",
          "Upload document",
          "Create signing request",
          "Review signingPayload",
          "Confirm signing",
          "Sign in browser",
          "Submit signedPackage",
          "Verify report",
          "Revoke and verify again"
        ].map((item, index) => (
          <div key={item} className="flowStep">
            <span>{String(index + 1).padStart(2, "0")}</span>
            <strong>{item}</strong>
          </div>
        ))}
      </div>

      <div className="documentTableWrap">
        <table className="documentTable">
          <thead>
            <tr>
              <th>Document name</th>
              <th>Signer</th>
              <th>Purpose</th>
              <th>Certificate serial</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>{file?.name ?? "No document selected"}</td>
              <td>{signer}</td>
              <td>{purposeLabel}</td>
              <td>{certificate?.serialNumber ?? "-"}</td>
              <td><StatusBadge status={status} /></td>
              <td>
                <div className="tableActions">
                  <button className="secondary" onClick={verifyCurrentPackage} disabled={!submitResult || loading}>Verify</button>
                  <button className="secondary" onClick={() => submitResult && downloadText("signed_package_v2.json", JSON.stringify(submitResult.signedPackage, null, 2))} disabled={!submitResult}>
                    Export
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div className="workflowPanels">
        <div className="surface">
          <h3>1. Key and X.509 demo certificate</h3>
          <div className="successBanner">
            <ShieldCheck size={16} />
            Browser generates the private key. The API receives publicKeyPem only.
          </div>
          <div className="formGrid">
            <label>
              Full name
              <input value={name} onChange={(event) => setName(event.target.value)} />
            </label>
            <label>
              Email
              <input value={email} onChange={(event) => setEmail(event.target.value)} />
            </label>
          </div>
          <button className="primary" onClick={createCertificate} disabled={loading}>
            <KeyRound size={18} />
            {loading ? "Working..." : "Generate key and request certificate"}
          </button>
          {certificate && (
            <dl className="detailList">
              <DetailItem label="Certificate type" value={certificate.certificateType} />
              <DetailItem label="Certificate serial" value={certificate.serialNumber} />
              <DetailItem label="Fingerprint" value={certificate.certificateFingerprint ?? "-"} />
            </dl>
          )}
        </div>

        <div className="surface">
          <h3>2. Document and signing request</h3>
          <FileInput label="Document" onFile={(selected) => {
            setFile(selected);
            setHashResult(null);
            setPrepareResult(null);
            setSubmitResult(null);
            setVerifyResult(null);
            setSigningConfirmed(false);
            setConfirmationCode("");
            setOtpRequest(null);
            setConfirmationResult(null);
            setStatus("draft");
          }} />
          <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
          <label>
            Signing purpose
            <select value={purpose} onChange={(event) => setPurpose(event.target.value)}>
              {signingPurposes.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </select>
          </label>
          <button className="primary" onClick={createSigningRequest} disabled={!certificate || !file || loading}>
            <Eye size={18} />
            Create signing request
          </button>
          {hashResult && (
            <dl className="detailList">
              <DetailItem label="Document hash" value={hashResult.documentHash} />
              <DetailItem label="Hash algorithm" value={hashResult.hashAlgorithm} />
            </dl>
          )}
        </div>
      </div>

      {prepareResult && (
        <div className="surface reviewPanel">
          <h3>3. Review signingPayload before signing</h3>
          <div className="warningBanner">
            <AlertTriangle size={16} />
            Check these fields before signing.
          </div>
          <dl className="detailList">
            <DetailItem label="documentName" value={prepareResult.signingPayload.documentName} />
            <DetailItem label="documentHash" value={prepareResult.signingPayload.documentHash} />
            <DetailItem label="signerName" value={prepareResult.signingPayload.signerName} />
            <DetailItem label="signerEmail" value={prepareResult.signingPayload.signerEmail} />
            <DetailItem label="certificateSerialNumber" value={prepareResult.signingPayload.certificateSerialNumber} />
            <DetailItem label="certificateFingerprint" value={prepareResult.signingPayload.certificateFingerprint} />
            <DetailItem label="signingPurpose" value={prepareResult.signingPayload.signingPurpose} />
            <DetailItem label="requestId" value={prepareResult.requestId} />
            <DetailItem label="nonce" value={prepareResult.nonce} />
          </dl>
          <div className="pinPanel">
            <h3>4. Xac nhan ky</h3>
            <label>
              Method
              <select value={confirmationMethod} onChange={(event) => {
                setConfirmationMethod(event.target.value as SigningConfirmationMethod);
                setConfirmationCode("");
                setSigningConfirmed(false);
                setConfirmationResult(null);
              }}>
                <option value="EMAIL_OTP">Email OTP fallback</option>
                <option value="TOTP">Authenticator TOTP</option>
              </select>
            </label>
            {confirmationMethod === "EMAIL_OTP" && (
              <button className="secondary" onClick={requestSigningOtp} disabled={loading || signingConfirmed}>
                <Mail size={18} />
                Request signing OTP
              </button>
            )}
            {otpRequest && confirmationMethod === "EMAIL_OTP" && (
              <dl className="detailList">
                <DetailItem label="OTP ID" value={String(otpRequest.otpId)} />
                <DetailItem label="Delivery" value={otpRequest.delivery} />
                <DetailItem label="Expires at" value={otpRequest.expiresAt} />
              </dl>
            )}
            <label>
              Confirmation code
              <input value={confirmationCode} onChange={(event) => setConfirmationCode(event.target.value)} inputMode="numeric" placeholder="6 digits" />
            </label>
            <button className="secondary" onClick={confirmSigningIntent} disabled={loading || !confirmationCode || signingConfirmed}>
              <ShieldCheck size={18} />
              Confirm signing request
            </button>
            {confirmationResult && <StatusLine ok={confirmationResult.confirmed} text={`${confirmationResult.confirmationMethod} confirmed at ${confirmationResult.confirmedAt}`} />}
            <button className="primary" onClick={signAndSubmit} disabled={loading || !prepareResult || !signingConfirmed}>
              <FileSignature size={18} />
              {loading ? "Signing..." : "Sign in browser and submit"}
            </button>
          </div>
        </div>
      )}

      {submitResult && (
        <div className="resultPanel">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>signedPackage accepted</h3>
              <p>Backend issued a demo timestamp token and returned a verification report.</p>
            </div>
          </div>
          <ReportPanel report={submitResult.verificationReport} />
          <PdfVisualStampPreview certificate={certificate} signedPackage={submitResult.signedPackage} purpose={purposeLabel} />
          <div className="buttonRow">
            <button className="secondary" onClick={verifyCurrentPackage}>
              <ClipboardCheck size={18} />
              Verify report
            </button>
            <button className="secondary" onClick={revokeAndVerifyAgain}>
              <RotateCcw size={18} />
              Revoke certificate and verify again
            </button>
            <button className="secondary" onClick={() => downloadText("signed_package_v2.json", JSON.stringify(submitResult.signedPackage, null, 2))}>
              <Download size={18} />
              Export signedPackage
            </button>
          </div>
        </div>
      )}

      {verifyResult && (
        <div className={verifyResult.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {verifyResult.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{verifyResult.valid ? "Verification passed" : "Verification failed"}</h3>
            <p>{verifyResult.reason}</p>
            <ReportPanel report={verifyResult.report} />
          </div>
        </div>
      )}

      {revokeResult && (
        <div className="warningBanner">
          <Ban size={16} />
          Certificate {revokeResult.serialNumber} was revoked for reason {revokeResult.reason}. Verifying the old package should now fail with certificate_revoked.
        </div>
      )}

      <div className="surface">
        <h3>Audit chain</h3>
        <button className="secondary" onClick={checkAuditChain}>
          <ShieldCheck size={18} />
          Verify audit hash chain
        </button>
        {auditResult && (
          <dl className="detailList">
            <DetailItem label="Audit chain valid" value={String(auditResult.valid)} />
            <DetailItem label="Total events" value={String(auditResult.totalEvents)} />
            <DetailItem label="Broken at" value={auditResult.brokenAt ? JSON.stringify(auditResult.brokenAt) : "none"} />
          </dl>
        )}
      </div>

      {error && <p className="errorText" role="alert">{error}</p>}
    </section>
  );
}

function StatusBadge({ status }: { status: DocumentStatus }) {
  return <span className={`statusBadge ${status}`}>{status}</span>;
}

function PdfVisualStampPreview({
  certificate,
  signedPackage,
  purpose
}: {
  certificate: Certificate | null;
  signedPackage: SignedPackageV2;
  purpose: string;
}) {
  return (
    <div className="visualStampPanel">
      <div>
        <h3>PDF visual stamp demo</h3>
        <p>Visual stamp is not PAdES.</p>
      </div>
      <div className="visualStamp">
        <strong>Signed by {certificate?.ownerName ?? signedPackage.signingPayload.signerName}</strong>
        <span>Email: {certificate?.email ?? signedPackage.signingPayload.signerEmail}</span>
        <span>Certificate serial: {certificate?.serialNumber ?? signedPackage.signingPayload.certificateSerialNumber}</span>
        <span>Signing time: {signedPackage.signedAtClient ?? "client time not provided"}</span>
        <span>Reason: {purpose}</span>
      </div>
    </div>
  );
}

function HashDocument() {
  const [file, setFile] = useState<File | null>(null);
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [result, setResult] = useState<HashResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    setError("");
    setResult(null);
    try {
      setResult(await hashDocument(file, hashAlgorithm));
    } catch (err) {
      setError(errorMessage(err, "Cannot hash document."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Hash document" description="Compute the document digest used by signing and verification flows." />
      <div className="surface">
        <FileInput label="Document" onFile={setFile} />
        <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
        <button className="primary" onClick={submit}>
          <Hash size={18} />
          Hash document
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel" aria-label="Hash result">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Hash computed</h3>
              <p>{result.documentName}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Hash algorithm" value={result.hashAlgorithm} />
            <DetailItem label="Document hash" value={result.documentHash} />
          </dl>
        </div>
      )}
    </section>
  );
}

function GenerateKeys() {
  const [name, setName] = useState("Nguyen Van A");
  const [email, setEmail] = useState("student@example.com");
  const [result, setResult] = useState<(X509IssueResponse & { privateKeyPem: string; publicKeyPem: string }) | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit() {
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const keyPair = await generateBrowserSigningKeyPair();
      const certificateResponse = await issueX509Certificate({ name, email, publicKeyPem: keyPair.publicKeyPem });
      setResult({ ...certificateResponse, ...keyPair });
    } catch (err) {
      setError(errorMessage(err, "Cannot generate browser keys or issue X.509 certificate."));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Create browser key pair and X.509 certificate" description="Generate an RSA 3072-bit key pair in the browser, then send only the public key to the SecureDoc demo CA." />
      <div className="surface">
        <div className="successBanner">
          <ShieldCheck size={16} />
          The private key is generated locally by Web Crypto. The API receives publicKeyPem only and issues an x509-demo certificate.
        </div>
        <div className="formGrid">
          <label>
            Full name
            <input value={name} onChange={(event) => setName(event.target.value)} />
          </label>
          <label>
            Email
            <input value={email} onChange={(event) => setEmail(event.target.value)} />
          </label>
        </div>
        <button className="primary" onClick={submit} disabled={loading}>
          <KeyRound size={18} />
          {loading ? "Creating..." : "Create browser key pair"}
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="outputStack" aria-label="Key generation result">
          <PemBlock title="Private key PEM" value={result.privateKeyPem} filename="private_key.pem" />
          <PemBlock title="Public key PEM" value={result.publicKeyPem} filename="public_key.pem" />
          <PemBlock title="User signing certificate PEM" value={result.userCertificatePem} filename="user_certificate.pem" />
          <PemBlock title="Demo intermediate CA PEM" value={result.intermediateCertificatePem} filename="demo_intermediate_ca.pem" />
          <PemBlock title="Demo root CA PEM" value={result.rootCertificatePem} filename="demo_root_ca.pem" />
          <PemBlock title="X.509 demo signer certificate JSON" value={JSON.stringify(result.certificate, null, 2)} filename="x509_demo_certificate.json" />
        </div>
      )}
    </section>
  );
}

type V2Step = "input" | "review" | "signed";

function SignDocumentV2() {
  const [step, setStep] = useState<V2Step>("input");
  const [file, setFile] = useState<File | null>(null);
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [certificateText, setCertificateText] = useState("");
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [purpose, setPurpose] = useState("approve_document");
  const [prepareResult, setPrepareResult] = useState<PrepareResponse | null>(null);
  const [submitResult, setSubmitResult] = useState<SubmitResponse | null>(null);
  const [signingConfirmed, setSigningConfirmed] = useState(false);
  const [confirmationMethod, setConfirmationMethod] = useState<SigningConfirmationMethod>("EMAIL_OTP");
  const [confirmationCode, setConfirmationCode] = useState("");
  const [otpRequest, setOtpRequest] = useState<SigningOtpRequestResponse | null>(null);
  const [confirmationResult, setConfirmationResult] = useState<SigningConfirmResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function prepare() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    const certificate = parseCertificate(certificateText, setError);
    if (!certificate) return;
    setError("");
    setSubmitResult(null);
    setLoading(true);
    try {
      const hash = await hashDocument(file, hashAlgorithm);
      const response = await prepareSigningRequest({
        documentName: file.name,
        documentHash: hash.documentHash,
        hashAlgorithm: hash.hashAlgorithm,
        certificateSerialNumber: certificate.serialNumber,
        signingPurpose: purpose,
        signerEmail: certificate.email
      });
      setPrepareResult(response);
      setSigningConfirmed(false);
      setConfirmationCode("");
      setOtpRequest(null);
      setConfirmationResult(null);
      setStep("review");
    } catch (err) {
      setError(errorMessage(err, "Cannot create signing request."));
    } finally {
      setLoading(false);
    }
  }

  async function requestOtpForSigning() {
    if (!prepareResult) return;
    setError("");
    setLoading(true);
    try {
      setOtpRequest(await requestSigningEmailOtp(prepareResult.requestId, prepareResult.signingPayload.signerEmail));
    } catch (err) {
      setError(errorMessage(err, "Cannot request signing OTP."));
    } finally {
      setLoading(false);
    }
  }

  async function confirmIntent() {
    if (!prepareResult) return;
    setError("");
    setLoading(true);
    try {
      const response = await confirmSigningRequest({
        requestId: prepareResult.requestId,
        signerEmail: prepareResult.signingPayload.signerEmail,
        method: confirmationMethod,
        code: confirmationCode
      });
      setConfirmationResult(response);
      setSigningConfirmed(response.confirmed);
    } catch (err) {
      setSigningConfirmed(false);
      setError(errorMessage(err, "Cannot confirm signing request."));
    } finally {
      setLoading(false);
    }
  }

  async function sign() {
    if (!prepareResult) return;
    if (!signingConfirmed) {
      setError("Confirm the signing payload before signing.");
      return;
    }
    if (!privateKeyPem.trim()) {
      setError("Paste or upload the private key PEM.");
      return;
    }
    const certificate = parseCertificate(certificateText, setError);
    if (!certificate) return;
    if (certificate.serialNumber !== prepareResult.signingPayload.certificateSerialNumber) {
      setError("Certificate serial changed after prepare.");
      return;
    }
    if (!certificate.userCertificatePem || !certificate.intermediateCertificatePem || !certificate.rootCertificatePem) {
      setError("X.509 demo certificate JSON is missing PEM chain fields.");
      return;
    }
    const signingHash = prepareResult.signingPayload.hashAlgorithm;
    if (!browserSigningHashSupported(signingHash)) {
      setError("Browser Web Crypto cannot RSA-PSS sign with SHA3-256. Use SHA-256, SHA-384, SHA-512, or submit an externally created SHA3 package.");
      return;
    }

    setError("");
    setLoading(true);
    try {
      const canonicalPayload = canonicalizePayload(prepareResult.signingPayload);
      const key = await importPrivateKey(privateKeyPem, signingHash);
      const signatureBase64 = await signPayload(key, canonicalPayload, signingHash);
      const signedPackage: SignedPackageV2 = {
        packageVersion: "2.0",
        signingPayload: prepareResult.signingPayload,
        payloadCanonicalization: "JSON-canonical-sorted-keys",
        signatureAlgorithm: "RSA-PSS",
        signatureBase64,
        userCertificatePem: certificate.userCertificatePem,
        intermediateCertificatePem: certificate.intermediateCertificatePem,
        rootCertificatePem: certificate.rootCertificatePem,
        trustedRootId: "securedoc-demo-root",
        signerCertificate: certificate,
        signedAtClient: new Date().toISOString()
      };
      const response = await submitSignature(signedPackage);
      setSubmitResult(response);
      setStep("signed");
    } catch (err) {
      setError(errorMessage(err, "Cannot sign or submit package."));
    } finally {
      setLoading(false);
    }
  }

  function reset() {
    setStep("input");
    setPrepareResult(null);
    setSubmitResult(null);
    setSigningConfirmed(false);
    setConfirmationCode("");
    setOtpRequest(null);
    setConfirmationResult(null);
    setError("");
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Sign v2 - client-side" description="Create a signing request, confirm the signing intent, sign canonical JSON in the browser, then submit the signed package." />

      {step === "input" && (
        <div className="surface">
          <div className="warningBanner">
            <ShieldCheck size={16} />
            The private key is used only by browser Web Crypto in this v2 flow. It is not sent to the API.
          </div>
          <FileInput label="Document" onFile={setFile} />
          <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
          <label>
            Signing purpose
            <select value={purpose} onChange={(event) => setPurpose(event.target.value)}>
              {signingPurposes.map((item) => (
                <option key={item.value} value={item.value}>{item.label}</option>
              ))}
            </select>
          </label>
          <TextOrFile label="X.509 demo signer certificate JSON" value={certificateText} setValue={setCertificateText} />
          <TextOrFile label="Private key PEM (local browser use only)" value={privateKeyPem} setValue={setPrivateKeyPem} />
          <button className="primary" onClick={prepare} disabled={loading}>
            <Eye size={18} />
            {loading ? "Preparing..." : "Create signing request"}
          </button>
          {error && <p className="errorText" role="alert">{error}</p>}
        </div>
      )}

      {step === "review" && prepareResult && (
        <div className="surface reviewPanel">
          <h3>Review before signing</h3>
          <div className="warningBanner">
            <AlertTriangle size={16} />
            Check these fields before signing.
          </div>
          <dl className="detailList">
            <DetailItem label="Document" value={prepareResult.signingPayload.documentName} />
            <DetailItem label="Document hash" value={prepareResult.signingPayload.documentHash} />
            <DetailItem label="Hash algorithm" value={prepareResult.signingPayload.hashAlgorithm} />
            <DetailItem label="Signer" value={`${prepareResult.signingPayload.signerName} (${prepareResult.signingPayload.signerEmail})`} />
            <DetailItem label="Certificate serial" value={prepareResult.signingPayload.certificateSerialNumber} />
            <DetailItem label="Certificate fingerprint" value={prepareResult.signingPayload.certificateFingerprint} />
            <DetailItem label="Signing purpose" value={prepareResult.signingPayload.signingPurpose} />
            <DetailItem label="Request ID" value={prepareResult.requestId} />
            <DetailItem label="Nonce" value={prepareResult.nonce} />
            <DetailItem label="Canonicalization" value="JSON-canonical-sorted-keys" />
          </dl>
          {prepareResult.warnings.length > 0 && <WarningList warnings={prepareResult.warnings} />}
          <div className="pinPanel">
            <h3>Xac nhan ky</h3>
            <label>
              Method
              <select value={confirmationMethod} onChange={(event) => {
                setConfirmationMethod(event.target.value as SigningConfirmationMethod);
                setConfirmationCode("");
                setSigningConfirmed(false);
                setConfirmationResult(null);
              }}>
                <option value="EMAIL_OTP">Email OTP fallback</option>
                <option value="TOTP">Authenticator TOTP</option>
              </select>
            </label>
            {confirmationMethod === "EMAIL_OTP" && (
              <button className="secondary" onClick={requestOtpForSigning} disabled={loading || signingConfirmed}>
                <Mail size={18} />
                Request signing OTP
              </button>
            )}
            {otpRequest && confirmationMethod === "EMAIL_OTP" && (
              <dl className="detailList">
                <DetailItem label="OTP ID" value={String(otpRequest.otpId)} />
                <DetailItem label="Delivery" value={otpRequest.delivery} />
                <DetailItem label="Expires at" value={otpRequest.expiresAt} />
              </dl>
            )}
            <label>
              Confirmation code
              <input value={confirmationCode} onChange={(event) => setConfirmationCode(event.target.value)} inputMode="numeric" placeholder="6 digits" />
            </label>
            <button className="secondary" onClick={confirmIntent} disabled={loading || !confirmationCode || signingConfirmed}>
              <ShieldCheck size={18} />
              Confirm signing request
            </button>
            {confirmationResult && <StatusLine ok={confirmationResult.confirmed} text={`${confirmationResult.confirmationMethod} confirmed at ${confirmationResult.confirmedAt}`} />}
          </div>
          <div className="buttonRow">
            <button className="primary" onClick={sign} disabled={loading || !signingConfirmed}>
              <FileSignature size={18} />
              {loading ? "Signing..." : "Sign in browser"}
            </button>
            <button className="secondary" onClick={reset}>Cancel</button>
          </div>
          {error && <p className="errorText" role="alert">{error}</p>}
        </div>
      )}

      {step === "signed" && submitResult && (
        <div className="resultPanel">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Signed package accepted</h3>
              <p>Request ID: {submitResult.requestId}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Received at server" value={submitResult.receivedAtServer} />
            <DetailItem label="Final decision" value={submitResult.verificationReport.finalDecision} />
            <DetailItem label="Signature" value={`${submitResult.signedPackage.signatureBase64.slice(0, 120)}...`} />
          </dl>
          {submitResult.warnings.length > 0 && <WarningList warnings={submitResult.warnings} />}
          <ReportPanel report={submitResult.verificationReport} />
          <div className="buttonRow">
            <button className="secondary" onClick={() => downloadText("signed_package_v2.json", JSON.stringify(submitResult.signedPackage, null, 2))}>
              <Download size={18} />
              Download signed_package_v2.json
            </button>
            <button className="secondary" onClick={reset}>Sign another document</button>
          </div>
        </div>
      )}
    </section>
  );
}

function VerifyDocumentV2() {
  const [file, setFile] = useState<File | null>(null);
  const [packageText, setPackageText] = useState("");
  const [result, setResult] = useState<VerifyV2Response | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose the original document first.");
      return;
    }
    setError("");
    setResult(null);
    try {
      const parsedPackage = JSON.parse(packageText) as SignedPackageV2;
      const packageHashAlgorithm = (parsedPackage.signingPayload?.hashAlgorithm ?? "SHA-256") as HashAlgorithm;
      const hash = await hashDocument(file, packageHashAlgorithm);
      setResult(await verifyV2({ documentHash: hash.documentHash, hashAlgorithm: hash.hashAlgorithm, signedPackage: parsedPackage }));
    } catch (err) {
      setError(errorMessage(err, "Cannot verify signed package."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Verify v2 package" description="Upload the original document and a v2 signed package to get a detailed verification report." />
      <div className="surface">
        <FileInput label="Original document" onFile={setFile} />
        <TextOrFile label="signed_package_v2.json" value={packageText} setValue={setPackageText} />
        <button className="primary" onClick={submit}>
          <ClipboardCheck size={18} />
          Verify v2
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Signature is valid" : "Signature is invalid"}</h3>
            <p>{result.reason}</p>
            {result.signer && <p>Signer: {result.signer.name} ({result.signer.email}), serial {result.signer.serialNumber}</p>}
            <ReportPanel report={result.report} />
          </div>
        </div>
      )}
    </section>
  );
}

function RevokeCertificate() {
  const [certificateText, setCertificateText] = useState("");
  const [serialNumber, setSerialNumber] = useState("");
  const [reason, setReason] = useState("key_compromise");
  const [result, setResult] = useState<{ serialNumber: string; status: string; reason: string; revokedAt: string } | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    setError("");
    setResult(null);
    let serial = serialNumber.trim();
    if (!serial && certificateText.trim()) {
      const certificate = parseCertificate(certificateText, setError);
      if (!certificate) return;
      serial = certificate.serialNumber;
      setSerialNumber(serial);
    }
    if (!serial) {
      setError("Enter a certificate serial number or upload certificate JSON.");
      return;
    }
    try {
      setResult(await revokeCertificate({ serialNumber: serial, reason, revokedBy: "local-demo-user" }));
    } catch (err) {
      setError(errorMessage(err, "Cannot revoke certificate."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Revoke certificate" description="Revoke by server DB serial number. Verification does not trust package status." />
      <div className="surface">
        <label>
          Serial number
          <input value={serialNumber} onChange={(event) => setSerialNumber(event.target.value)} placeholder="Certificate serial" />
        </label>
        <label>
          Revocation reason
          <input value={reason} onChange={(event) => setReason(event.target.value)} />
        </label>
        <TextOrFile label="Optional certificate JSON (to fill serial)" value={certificateText} setValue={setCertificateText} />
        <button className="primary" onClick={submit}>
          <RotateCcw size={18} />
          Revoke certificate
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel">
          <div className="resultHeader">
            <Ban size={22} />
            <div>
              <h3>Certificate revoked</h3>
              <p>Serial: {result.serialNumber}</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Status" value={result.status} />
            <DetailItem label="Reason" value={result.reason} />
            <DetailItem label="Revoked at" value={result.revokedAt} />
          </dl>
        </div>
      )}
    </section>
  );
}

function SignDocumentLegacy() {
  const [file, setFile] = useState<File | null>(null);
  const [privateKey, setPrivateKey] = useState("");
  const [certificate, setCertificate] = useState("");
  const [hashAlgorithm, setHashAlgorithm] = useState<HashAlgorithm>("SHA-256");
  const [result, setResult] = useState<LegacySignedPackage | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    body.append("privateKeyPem", privateKey);
    body.append("certificate", certificate);
    body.append("hashAlgorithm", hashAlgorithm);
    try {
      const response = await fetch(`${API_BASE}/api/sign`, { method: "POST", body });
      setResult(await parseResponse<LegacySignedPackage>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot sign document."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Insecure legacy demo sign endpoint" description="This compatibility endpoint sends privateKeyPem and a legacy-demo JSON certificate to the backend." />
      <div className="surface">
        <div className="warningBanner">
          <AlertTriangle size={16} />
          Insecure legacy demo: backend receives privateKeyPem. Use Documents for the main flow.
        </div>
        <FileInput label="Document" onFile={setFile} />
        <HashAlgorithmSelect value={hashAlgorithm} setValue={setHashAlgorithm} />
        <TextOrFile label="Private key PEM" value={privateKey} setValue={setPrivateKey} />
        <TextOrFile label="Legacy-demo JSON certificate" value={certificate} setValue={setCertificate} />
        <button className="primary" onClick={submit}>
          <FileSignature size={18} />
          Sign with legacy API
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className="resultPanel" aria-label="Legacy signing result">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Legacy signed package created</h3>
              <p>Use only for old verify flow demonstrations.</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="Document hash" value={result.documentHash} />
            <DetailItem label="Hash algorithm" value={result.hashAlgorithm} />
            <DetailItem label="Signed at" value={result.signedAt} />
            <DetailItem label="Signature" value={`${result.signatureBase64.slice(0, 120)}...`} />
          </dl>
          <button className="secondary" onClick={() => downloadText("signed_package_legacy.json", JSON.stringify(result, null, 2))}>
            <Download size={18} />
            Download legacy package
          </button>
        </div>
      )}
    </section>
  );
}

function VerifyDocumentLegacy() {
  const [file, setFile] = useState<File | null>(null);
  const [packageText, setPackageText] = useState("");
  const [result, setResult] = useState<LegacyVerifyResult | null>(null);
  const [error, setError] = useState("");

  async function submit() {
    if (!file) {
      setError("Choose a document first.");
      return;
    }
    setError("");
    setResult(null);
    const body = new FormData();
    body.append("file", file);
    body.append("signedPackage", packageText);
    try {
      const response = await fetch(`${API_BASE}/api/verify`, { method: "POST", body });
      setResult(await parseResponse<LegacyVerifyResult>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot verify document."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Legacy verify endpoint" description="Verifies old packages that signed only the document hash." />
      <div className="surface">
        <FileInput label="Document" onFile={setFile} />
        <TextOrFile label="signed_package_legacy.json" value={packageText} setValue={setPackageText} />
        <button className="primary" onClick={submit}>
          <FileCheck size={18} />
          Verify legacy package
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>
      {result && (
        <div className={result.valid ? "verifyBox valid" : "verifyBox invalid"} role="status" aria-live="polite">
          <div className="statusIcon" aria-hidden="true">
            {result.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}
          </div>
          <div>
            <h3>{result.valid ? "Legacy signature valid" : "Legacy signature invalid"}</h3>
            <p>{result.reason}</p>
            {result.signer && <p>Signer: {result.signer.name} ({result.signer.email})</p>}
            {Array.isArray(result.details.verificationSteps) && <StepsList steps={result.details.verificationSteps} />}
            <pre>{JSON.stringify(result.details, null, 2)}</pre>
          </div>
        </div>
      )}
    </section>
  );
}

function BlindSignatureDemo() {
  const [purpose, setPurpose] = useState<BlindPurpose>("anonymous_access_token");
  const [session, setSession] = useState<BlindSessionResponse | null>(null);
  const [signResult, setSignResult] = useState<BlindSignResponse | null>(null);
  const [finalSignatureBase64, setFinalSignatureBase64] = useState("");
  const [verifyResult, setVerifyResult] = useState<BlindVerifyResponse | null>(null);
  const [redeemResult, setRedeemResult] = useState<BlindRedeemResponse | null>(null);
  const [redeemAgainResult, setRedeemAgainResult] = useState<BlindRedeemResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function createSession() {
    setError("");
    setSession(null);
    setSignResult(null);
    setFinalSignatureBase64("");
    setVerifyResult(null);
    setRedeemResult(null);
    setRedeemAgainResult(null);
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/blind-signature/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ purpose, ttlSeconds: 600 })
      });
      setSession(await parseResponse<BlindSessionResponse>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot create blind signature session."));
    } finally {
      setLoading(false);
    }
  }

  async function signBlinded() {
    if (!session) return;
    setError("");
    setLoading(true);
    try {
      const response = await fetch(`${API_BASE}/api/blind-signature/sign`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: session.sessionId,
          blindedMessageBase64: session.blindedMessageBase64
        })
      });
      setSignResult(await parseResponse<BlindSignResponse>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot sign blinded token."));
    } finally {
      setLoading(false);
    }
  }

  function unblind() {
    if (!session?.blindingFactorBase64 || !signResult?.blindSignatureBase64) {
      setError("Create session and sign blinded token first.");
      return;
    }
    try {
      setFinalSignatureBase64(
        unblindSignatureInBrowser(
          signResult.blindSignatureBase64,
          session.blindingFactorBase64,
          session.publicKey.modulusBase64
        )
      );
      setError("");
    } catch (err) {
      setError(errorMessage(err, "Cannot unblind signature in browser."));
    }
  }

  async function verifyFinal() {
    if (!session || !finalSignatureBase64) return;
    setError("");
    try {
      const response = await fetch(`${API_BASE}/api/blind-signature/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: session.sessionId,
          token: session.token,
          finalSignatureBase64
        })
      });
      setVerifyResult(await parseResponse<BlindVerifyResponse>(response));
    } catch (err) {
      setError(errorMessage(err, "Cannot verify final blind signature."));
    }
  }

  async function redeem(again = false) {
    if (!session || !finalSignatureBase64) return;
    setError("");
    try {
      const response = await fetch(`${API_BASE}/api/blind-signature/redeem`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sessionId: session.sessionId,
          token: session.token,
          finalSignatureBase64
        })
      });
      const data = await parseResponse<BlindRedeemResponse>(response);
      if (again) setRedeemAgainResult(data);
      else setRedeemResult(data);
    } catch (err) {
      setError(errorMessage(err, "Cannot redeem blind token."));
    }
  }

  return (
    <section className="page taskPage">
      <PageHeader title="Blind signature token demo" description="Privacy-oriented flow: create token, blind it, signer signs only the blinded token, browser unblinds, verifies, redeems, then shows double-spend failure." />
      <div className="surface">
        <div className="warningBanner">
          <AlertTriangle size={16} />
          Educational demo only. Blind signatures are for privacy/anonymous-token problems, not document identity signing.
        </div>
        <label>
          Purpose
          <select value={purpose} onChange={(event) => setPurpose(event.target.value as BlindPurpose)}>
            <option value="anonymous_access_token">anonymous_access_token</option>
            <option value="e_voting_demo">e_voting_demo</option>
            <option value="e_cash_demo">e_cash_demo</option>
          </select>
        </label>
        <button className="primary" onClick={createSession} disabled={loading}>
          <EyeOff size={18} />
          {loading ? "Creating..." : "1. Create token and blind it"}
        </button>
        {error && <p className="errorText" role="alert">{error}</p>}
      </div>

      {session && (
        <div className="resultPanel">
          <div className="resultHeader">
            <CheckCircle2 size={22} />
            <div>
              <h3>Token created and blinded</h3>
              <p>Signer cannot see the raw token; it receives only blindedMessageBase64.</p>
            </div>
          </div>
          <dl className="detailList">
            <DetailItem label="tokenId" value={session.token.tokenId} />
            <DetailItem label="purpose" value={session.token.purpose} />
            <DetailItem label="createdAt" value={session.token.createdAt} />
            <DetailItem label="expiresAt" value={session.token.expiresAt} />
            <DetailItem label="nonce" value={session.token.nonce} />
            <DetailItem label="tokenVersion" value={session.token.tokenVersion} />
            <DetailItem label="tokenHash" value={session.tokenHash} />
            <DetailItem label="blindedMessageBase64" value={`${session.blindedMessageBase64.slice(0, 180)}...`} />
          </dl>
          <div className="warningBanner">
            <AlertTriangle size={16} />
            Demo reveals blindingFactorBase64 so the browser can show unblind step. Do not expose this in production.
          </div>
          <div className="buttonRow">
            <button className="primary" onClick={signBlinded} disabled={loading}>
              <FileSignature size={18} />
              2. Sign blinded token
            </button>
          </div>
        </div>
      )}

      {signResult && (
        <div className="resultPanel">
          <h3>Blinded token signed</h3>
          <dl className="detailList">
            <DetailItem label="blindSignatureBase64" value={`${signResult.blindSignatureBase64.slice(0, 180)}...`} />
            <DetailItem label="signer warning" value={signResult.warning} />
          </dl>
          <button className="primary" onClick={unblind}>
            <Eye size={18} />
            3. Unblind in browser
          </button>
        </div>
      )}

      {finalSignatureBase64 && session && (
        <div className="resultPanel">
          <h3>Final signature ready</h3>
          <dl className="detailList">
            <DetailItem label="finalSignatureBase64" value={`${finalSignatureBase64.slice(0, 180)}...`} />
          </dl>
          <div className="buttonRow">
            <button className="primary" onClick={verifyFinal}>
              <ClipboardCheck size={18} />
              4. Verify final signature
            </button>
            <button className="secondary" onClick={() => redeem(false)}>
              <CheckCircle2 size={18} />
              5. Redeem token
            </button>
            <button className="secondary" onClick={() => redeem(true)}>
              <Ban size={18} />
              6. Redeem again
            </button>
          </div>
        </div>
      )}

      {verifyResult && (
        <div className={verifyResult.valid ? "verifyBox valid" : "verifyBox invalid"}>
          <div className="statusIcon">{verifyResult.valid ? <BadgeCheck size={24} /> : <Ban size={24} />}</div>
          <div>
            <h3>{verifyResult.valid ? "Final blind signature valid" : "Final blind signature invalid"}</h3>
            <p>{verifyResult.reason}</p>
          </div>
        </div>
      )}

      {(redeemResult || redeemAgainResult) && (
        <div className="resultPanel">
          <h3>Redeem results</h3>
          <dl className="detailList">
            {redeemResult && <DetailItem label="First redeem" value={`${redeemResult.redeemed ? "success" : "failed"}: ${redeemResult.reason}`} />}
            {redeemAgainResult && <DetailItem label="Second redeem" value={`${redeemAgainResult.redeemed ? "success" : "failed"}: ${redeemAgainResult.reason}`} />}
          </dl>
        </div>
      )}
    </section>
  );
}

function ReportPanel({ report }: { report: VerificationReport }) {
  const cells: Array<[string, string]> = [
    ["Crypto valid", formatBoolean(report.cryptoValid)],
    ["Document hash valid", formatBoolean(report.documentHashValid)],
    ["Trusted chain valid", formatBoolean(report.trustedChainValid)],
    ["Revocation valid", formatBoolean(report.revocationValid)],
    ["Timestamp valid", formatBoolean(report.timestampValid)],
    ["Server accepted", formatBoolean(report.serverAccepted)],
    ["Request confirmed", formatBoolean(report.signingRequestConfirmed)],
    ["Confirmation method", report.confirmationMethod ?? "none"],
    ["Legal ready", formatBoolean(report.legalReady)],
    ["Document integrity", report.documentIntegrity],
    ["Signing payload", report.signingPayloadValid],
    ["Signature", report.signatureValid],
    ["Certificate parsed", report.certificateParsed],
    ["Certificate trusted", report.certificateTrusted],
    ["Certificate type", report.certificateType],
    ["Chain", report.certificateChainValid],
    ["Validity period", report.certificateValidityPeriod],
    ["Revocation", report.certificateRevocationStatus],
    ["Revocation source", report.revocationSource],
    ["Key usage", report.keyUsageValid],
    ["Algorithm policy", report.algorithmPolicyValid],
    ["Replay", report.replayCheck],
    ["Timestamp", report.timestampStatus],
    ["Final decision", report.finalDecision]
  ];

  return (
    <div className="reportPanel">
      <div className="reportGrid">
        {cells.map(([label, value]) => (
          <ReportCell key={label} label={label} value={value} />
        ))}
      </div>
      {report.errors.length > 0 && <WarningList warnings={report.errors} />}
      {report.warnings.length > 0 && <WarningList warnings={report.warnings} />}
      <StepsList steps={report.verificationSteps} />
    </div>
  );
}

function formatBoolean(value: boolean): string {
  return value ? "valid" : "invalid";
}

function ReportCell({ label, value }: { label: string; value: string }) {
  const good = value === "passed" || value === "valid";
  const bad = value === "failed" || value === "invalid" || value === "revoked";
  return (
    <div className={good ? "reportCell ok" : bad ? "reportCell bad" : "reportCell warn"}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function WarningList({ warnings }: { warnings: string[] }) {
  return (
    <div className="warningBanner">
      <AlertTriangle size={16} />
      <span>{warnings.join(" | ")}</span>
    </div>
  );
}

function StepsList({ steps }: { steps: VerificationStep[] }) {
  return (
    <ol className="verifySteps">
      {steps.map((item, index) => (
        <li key={`${item.step}-${index}`} className={item.status === "passed" ? "passed" : item.status === "failed" ? "failed" : "warning"}>
          <strong>{item.step}</strong>
          <span>{item.message}</span>
        </li>
      ))}
    </ol>
  );
}

function PageHeader({ title, description }: { title: string; description: string }) {
  return (
    <div className="pageHeader compact">
      <h2>{title}</h2>
      <p>{description}</p>
    </div>
  );
}

function DetailItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function FileInput({ label, onFile }: { label: string; onFile: (file: File | null) => void }) {
  return (
    <label className="fileRow">
      <span>{label}</span>
      <span className="fileControl">
        <Upload size={18} />
        <input type="file" onChange={(event) => onFile(event.target.files?.[0] ?? null)} />
      </span>
    </label>
  );
}

function HashAlgorithmSelect({ value, setValue }: { value: HashAlgorithm; setValue: (value: HashAlgorithm) => void }) {
  const selected = hashAlgorithmOptions.find((item) => item.value === value);

  return (
    <label>
      Hash algorithm
      <select value={value} onChange={(event) => setValue(event.target.value as HashAlgorithm)}>
        {hashAlgorithmOptions.map((item) => (
          <option key={item.value} value={item.value}>{item.label}</option>
        ))}
      </select>
      {selected && <small className="fieldHint">{selected.helper}</small>}
    </label>
  );
}

function TextOrFile({ label, value, setValue }: { label: string; value: string; setValue: (value: string) => void }) {
  const id = useId();

  async function readFile(file: File | null) {
    if (file) setValue(await file.text());
  }

  return (
    <label htmlFor={id} className="textFileField">
      <span>{label}</span>
      <input type="file" onChange={(event) => readFile(event.target.files?.[0] ?? null)} />
      <textarea id={id} value={value} onChange={(event) => setValue(event.target.value)} spellCheck={false} />
    </label>
  );
}

function PemBlock({ title, value, filename }: { title: string; value: string; filename: string }) {
  return (
    <article className="pemBlock">
      <header>
        <h3>{title}</h3>
        <button className="iconButton" onClick={() => downloadText(filename, value)} title={`Download ${filename}`} aria-label={`Download ${filename}`}>
          <Download size={18} />
        </button>
      </header>
      <pre>{value}</pre>
    </article>
  );
}

function parseCertificate(value: string, setError: (value: string) => void): Certificate | null {
  try {
    const certificate = JSON.parse(value) as Certificate;
    if (!certificate.serialNumber || !certificate.publicKeyPem) {
      setError("Certificate JSON is missing serialNumber or publicKeyPem.");
      return null;
    }
    return certificate;
  } catch {
    setError("Certificate JSON is invalid.");
    return null;
  }
}

async function parseResponse<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : "Request failed";
    throw new Error(detail);
  }
  return data as T;
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

function downloadText(filename: string, content: string) {
  const blob = new Blob([content], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function unblindSignatureInBrowser(
  blindSignatureBase64: string,
  blindingFactorBase64: string,
  modulusBase64: string,
) {
  const modulusBytes = base64ToBytes(modulusBase64);
  const n = bytesToBigInt(modulusBytes);
  const blindSignature = bytesToBigInt(base64ToBytes(blindSignatureBase64));
  const blindingFactor = bytesToBigInt(base64ToBytes(blindingFactorBase64));
  const finalSignature = (blindSignature * modInverse(blindingFactor, n)) % n;
  return bytesToBase64(bigIntToBytes(finalSignature, modulusBytes.length));
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) + BigInt(byte);
  }
  return result;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let current = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return bytes;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let nextT = 1n;
  let r = modulus;
  let nextR = value % modulus;
  while (nextR !== 0n) {
    const quotient = r / nextR;
    [t, nextT] = [nextT, t - quotient * nextT];
    [r, nextR] = [nextR, r - quotient * nextR];
  }
  if (r > 1n) throw new Error("Value is not invertible.");
  return t < 0n ? t + modulus : t;
}

createRoot(document.getElementById("root")!).render(<App />);
