const API_BASE = "http://127.0.0.1:8000";

export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512" | "SHA3-256";

export type Certificate = {
  serialNumber: string;
  ownerName: string;
  email: string;
  publicKeyPem: string;
  issuer: string;
  issuedAt: string;
  expiresAt: string;
  status: string;
  caSignatureAlgorithm?: string;
  caSignatureBase64?: string;
};

export type SigningPayload = {
  documentName: string;
  documentHash: string;
  hashAlgorithm: HashAlgorithm;
  signatureAlgorithm: "RSA-PSS";
  signerName: string;
  signerEmail: string;
  certificateSerialNumber: string;
  certificateFingerprint: string;
  signingPurpose: string;
  createdAt: string;
  nonce: string;
  requestId: string;
  payloadVersion: string;
};

export type PrepareResponse = {
  requestId: string;
  nonce: string;
  signingPayload: SigningPayload;
  canonicalPayloadBase64: string;
  warnings: string[];
};

export type VerificationStep = {
  step: string;
  status: string;
  message: string;
};

export type VerificationReport = {
  documentIntegrity: string;
  signingPayloadValid: string;
  signatureValid: string;
  certificateParsed: string;
  certificateTrusted: string;
  certificateType: string;
  certificateChainValid: string;
  certificateValidityPeriod: string;
  certificateRevocationStatus: string;
  keyUsageValid: string;
  algorithmPolicyValid: string;
  replayCheck: string;
  timestampStatus: string;
  finalDecision: string;
  warnings: string[];
  verificationSteps: VerificationStep[];
};

export type SignedPackageV2 = {
  packageVersion: "2.0";
  signingPayload: SigningPayload;
  payloadCanonicalization: "JSON-canonical-sorted-keys";
  signatureAlgorithm: "RSA-PSS";
  signatureBase64: string;
  signerCertificate: Certificate;
  signedAtClient?: string;
  receivedAtServer?: string;
  verificationReport?: VerificationReport;
};

export type SubmitResponse = {
  accepted: boolean;
  requestId: string;
  receivedAtServer: string;
  verificationReport: VerificationReport;
  signedPackage: SignedPackageV2;
  warnings: string[];
};

export type VerifyV2Response = {
  valid: boolean;
  reason: string;
  signer: { name: string; email: string; serialNumber: string } | null;
  documentHash: string;
  signedAt: string | null;
  report: VerificationReport;
};

export async function prepareSigningRequest(body: {
  documentName: string;
  documentHash: string;
  hashAlgorithm: HashAlgorithm;
  certificateSerialNumber: string;
  signingPurpose: string;
}): Promise<PrepareResponse> {
  const response = await fetch(`${API_BASE}/api/sign/v2/prepare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handleResponse<PrepareResponse>(response);
}

export async function submitSignature(body: SignedPackageV2): Promise<SubmitResponse> {
  const response = await fetch(`${API_BASE}/api/sign/v2/submit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handleResponse<SubmitResponse>(response);
}

export async function verifyV2(body: {
  documentHash: string;
  hashAlgorithm: HashAlgorithm;
  signedPackage: unknown;
}): Promise<VerifyV2Response> {
  const response = await fetch(`${API_BASE}/api/verify/v2`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return handleResponse<VerifyV2Response>(response);
}

export async function hashDocument(file: File, hashAlgorithm: HashAlgorithm) {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("hashAlgorithm", hashAlgorithm);
  const response = await fetch(`${API_BASE}/api/documents/hash`, { method: "POST", body: formData });
  return handleResponse<{ documentName: string; hashAlgorithm: HashAlgorithm; documentHash: string }>(response);
}

export function canonicalizePayload(payload: SigningPayload): string {
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(payload).sort()) {
    sorted[key] = payload[key as keyof SigningPayload];
  }
  return JSON.stringify(sorted);
}

export function browserSigningHashSupported(hashAlgorithm: HashAlgorithm): hashAlgorithm is Exclude<HashAlgorithm, "SHA3-256"> {
  return hashAlgorithm === "SHA-256" || hashAlgorithm === "SHA-384" || hashAlgorithm === "SHA-512";
}

export async function importPrivateKey(pem: string, hashAlgorithm: Exclude<HashAlgorithm, "SHA3-256">): Promise<CryptoKey> {
  const base64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  const der = Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    der.buffer,
    { name: "RSA-PSS", hash: { name: hashAlgorithm } },
    false,
    ["sign"],
  );
}

export async function signPayload(
  privateKey: CryptoKey,
  canonicalJson: string,
  hashAlgorithm: Exclude<HashAlgorithm, "SHA3-256">,
): Promise<string> {
  const data = new TextEncoder().encode(canonicalJson);
  const signature = await crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: digestSize(hashAlgorithm) },
    privateKey,
    data,
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

function digestSize(hashAlgorithm: Exclude<HashAlgorithm, "SHA3-256">): number {
  if (hashAlgorithm === "SHA-512") return 64;
  if (hashAlgorithm === "SHA-384") return 48;
  return 32;
}

async function handleResponse<T>(response: Response): Promise<T> {
  const data = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : "Request failed";
    throw new Error(detail);
  }
  return data as T;
}
