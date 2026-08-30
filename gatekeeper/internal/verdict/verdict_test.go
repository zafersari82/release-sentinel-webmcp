package verdict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"testing"
	"time"
)

func testVerifierAndKey(t *testing.T) (*Verifier, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), "test-key")
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Unix(2_000_000_000, 0)
	v.Now = func() time.Time { return fixed }
	return v, priv
}

func signedRequest(t *testing.T, priv *ecdsa.PrivateKey, severity string, failed bool) Request {
	t.Helper()
	bundle := EvidenceBundle{
		Schema: evidenceSchema, ReleaseID: "r-current", SourceSHA256: string(make([]byte, 0)),
		ExecutionID: "exec-1", Nonce: "nonce-1", IssuedAtUnix: 1_999_999_900,
		ExpiresAtUnix: 2_000_000_100, PolicyID: "org", PolicyRevision: 1,
		PolicySHA256:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ExecutionCount: 1,
		Results:        []CheckResult{{FindingID: "f", Severity: severity, Failed: failed, BlockingEligible: true, EvidenceDigestSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}},
	}
	bundle.SourceSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	raw, err := canonicalBundleBytes(bundle)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return Request{
		ReleaseID: bundle.ReleaseID, SourceSHA256: bundle.SourceSHA256, PolicySHA256: bundle.PolicySHA256,
		SignedEvidenceBundle: SignedEvidenceBundle{Bundle: bundle, BundleSHA256: hex.EncodeToString(digest[:]), SignatureBase64: base64.StdEncoding.EncodeToString(sig), KeyID: "test-key"},
		AgentOpinions:        []AgentOpinion{{Agent: "a", Vote: "GO"}, {Agent: "b", Vote: "GO"}, {Agent: "c", Vote: "GO"}, {Agent: "d", Vote: "GO"}},
	}
}

func TestAllAgentsGoCannotOverrideVerifiedBlocker(t *testing.T) {
	verifier, priv := testVerifierAndKey(t)
	req := signedRequest(t, priv, "HIGH", true)
	got := DecideVerified(req, verifier)
	if !got.Accepted || !got.EvidenceVerified || got.Decision != "NO_GO" {
		t.Fatalf("expected verified NO_GO, got %+v", got)
	}
	if got.AgentInfluence != 0 || got.IgnoredAgentOpinions != 4 || got.LLMPresent {
		t.Fatalf("agent opinions influenced verdict: %+v", got)
	}
}

func TestTamperedSeverityIsRejected(t *testing.T) {
	verifier, priv := testVerifierAndKey(t)
	req := signedRequest(t, priv, "HIGH", true)
	req.SignedEvidenceBundle.Bundle.Results[0].Severity = "INFO"
	got := DecideVerified(req, verifier)
	if got.Accepted || got.Decision != "REJECTED" || got.RejectionCode != "DIGEST_MISMATCH" {
		t.Fatalf("tampered signed evidence must be rejected: %+v", got)
	}
}

func TestDeletedBlockerIsRejected(t *testing.T) {
	verifier, priv := testVerifierAndKey(t)
	req := signedRequest(t, priv, "HIGH", true)
	req.SignedEvidenceBundle.Bundle.Results = nil
	got := DecideVerified(req, verifier)
	if got.Accepted || got.RejectionCode != "DIGEST_MISMATCH" {
		t.Fatalf("deleted signed evidence must be rejected: %+v", got)
	}
}

func TestReplayAcrossReleaseContextIsRejected(t *testing.T) {
	verifier, priv := testVerifierAndKey(t)
	req := signedRequest(t, priv, "INFO", false)
	req.ReleaseID = "r-new"
	got := DecideVerified(req, verifier)
	if got.Accepted || got.RejectionCode != "CONTEXT_MISMATCH" {
		t.Fatalf("replayed evidence must be rejected: %+v", got)
	}
}
