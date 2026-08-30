package verdict

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const evidenceSchema = "release-sentinel.evidence-bundle.v1"

type Verifier struct {
	PublicKey *ecdsa.PublicKey
	KeyID     string
	Now       func() time.Time
}

func NewVerifier(publicPEM []byte, keyID string) (*Verifier, error) {
	block, _ := pem.Decode(publicPEM)
	if block == nil {
		return nil, errors.New("invalid evidence public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse evidence public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-256" {
		return nil, errors.New("evidence public key must be ECDSA P-256")
	}
	return &Verifier{PublicKey: pub, KeyID: keyID, Now: time.Now}, nil
}

func canonicalBundleBytes(bundle EvidenceBundle) ([]byte, error) {
	// Marshal through interface/map so JSON object keys are lexicographically sorted,
	// matching Python json.dumps(sort_keys=True,separators=(",", ":")).
	first, err := json.Marshal(bundle)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(first, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (v *Verifier) Verify(req Request) (EvidenceBundle, string, error) {
	signed := req.SignedEvidenceBundle
	bundle := signed.Bundle
	if bundle.Schema != evidenceSchema {
		return bundle, "SCHEMA_INVALID", errors.New("unsupported evidence schema")
	}
	if req.ReleaseID == "" || req.SourceSHA256 == "" || req.PolicySHA256 == "" {
		return bundle, "CONTEXT_MISSING", errors.New("release/source/policy context is required")
	}
	if bundle.ReleaseID != req.ReleaseID || bundle.SourceSHA256 != req.SourceSHA256 || bundle.PolicySHA256 != req.PolicySHA256 {
		return bundle, "CONTEXT_MISMATCH", errors.New("signed evidence is bound to a different release/source/policy context")
	}
	if !validSHA256Hex(bundle.SourceSHA256) || !validSHA256Hex(bundle.PolicySHA256) || bundle.ExecutionID == "" || bundle.Nonce == "" {
		return bundle, "BUNDLE_INVALID", errors.New("signed evidence context fields are invalid")
	}
	if v.KeyID != "" && signed.KeyID != v.KeyID {
		return bundle, "UNTRUSTED_ISSUER", errors.New("evidence key id is not trusted")
	}
	raw, err := canonicalBundleBytes(bundle)
	if err != nil {
		return bundle, "BUNDLE_INVALID", err
	}
	digest := sha256.Sum256(raw)
	if !strings.EqualFold(signed.BundleSHA256, hex.EncodeToString(digest[:])) {
		return bundle, "DIGEST_MISMATCH", errors.New("evidence digest does not match canonical payload")
	}
	sig, err := base64.StdEncoding.DecodeString(signed.SignatureBase64)
	if err != nil || len(sig) == 0 {
		return bundle, "SIGNATURE_INVALID", errors.New("evidence signature is not valid base64")
	}
	if !ecdsa.VerifyASN1(v.PublicKey, digest[:], sig) {
		return bundle, "SIGNATURE_INVALID", errors.New("evidence signature verification failed")
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	nowUnix := now.Unix()
	if bundle.IssuedAtUnix > nowUnix+30 {
		return bundle, "NOT_YET_VALID", errors.New("evidence issued-at time is in the future")
	}
	if bundle.ExpiresAtUnix <= nowUnix || bundle.ExpiresAtUnix-bundle.IssuedAtUnix > 900 {
		return bundle, "EVIDENCE_EXPIRED", errors.New("evidence has expired or exceeds maximum TTL")
	}
	if bundle.ExecutionCount < 1 {
		return bundle, "BUNDLE_INVALID", errors.New("evidence must contain at least one policy execution")
	}
	seen := map[string]struct{}{}
	for _, result := range bundle.Results {
		if result.FindingID == "" || !validSHA256Hex(result.EvidenceDigestSHA256) {
			return bundle, "BUNDLE_INVALID", errors.New("finding identity/digest is invalid")
		}
		if _, ok := seen[result.FindingID]; ok {
			return bundle, "BUNDLE_INVALID", errors.New("duplicate finding in signed evidence")
		}
		seen[result.FindingID] = struct{}{}
	}
	// Defensive assertion that canonical JSON didn't acquire insignificant whitespace.
	if bytes.Contains(raw, []byte("\n")) {
		return bundle, "BUNDLE_INVALID", errors.New("canonical evidence contains unexpected whitespace")
	}
	return bundle, "", nil
}
