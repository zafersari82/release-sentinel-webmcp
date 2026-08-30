package verdict

import "fmt"

type CheckResult struct {
	FindingID            string `json:"finding_id"`
	Severity             string `json:"severity"`
	Failed               bool   `json:"failed"`
	BlockingEligible     bool   `json:"blocking_eligible"`
	EvidenceDigestSHA256 string `json:"evidence_digest_sha256"`
}

type EvidenceBundle struct {
	Schema         string        `json:"schema"`
	ReleaseID      string        `json:"release_id"`
	SourceSHA256   string        `json:"source_sha256"`
	ExecutionID    string        `json:"execution_id"`
	Nonce          string        `json:"nonce"`
	IssuedAtUnix   int64         `json:"issued_at_unix"`
	ExpiresAtUnix  int64         `json:"expires_at_unix"`
	PolicyID       string        `json:"policy_id"`
	PolicyRevision int           `json:"policy_revision"`
	PolicySHA256   string        `json:"policy_sha256"`
	ExecutionCount int           `json:"execution_count"`
	Results        []CheckResult `json:"results"`
}

type SignedEvidenceBundle struct {
	Bundle          EvidenceBundle `json:"bundle"`
	BundleSHA256    string         `json:"bundle_sha256"`
	SignatureBase64 string         `json:"signature_base64"`
	KeyID           string         `json:"key_id"`
}

type AgentOpinion struct {
	Agent string `json:"agent"`
	Vote  string `json:"vote"`
	Note  string `json:"note,omitempty"`
}

type Request struct {
	ReleaseID            string               `json:"release_id"`
	SourceSHA256         string               `json:"source_sha256"`
	PolicySHA256         string               `json:"policy_sha256"`
	SignedEvidenceBundle SignedEvidenceBundle `json:"signed_evidence_bundle"`
	AgentOpinions        []AgentOpinion       `json:"agent_opinions,omitempty"`
}

type Response struct {
	Accepted              bool     `json:"accepted"`
	Decision              string   `json:"decision"`
	Rationale             []string `json:"rationale"`
	Authority             string   `json:"authority"`
	Component             string   `json:"component"`
	LLMPresent            bool     `json:"llm_present"`
	AgentInfluence        int      `json:"agent_influence"`
	IgnoredAgentOpinions  int      `json:"ignored_agent_opinions"`
	AuthoritativeBlockers int      `json:"authoritative_blockers"`
	AuthoritativeMedium   int      `json:"authoritative_medium"`
	EvidenceVerified      bool     `json:"evidence_verified"`
	VerifiedExecutionID   string   `json:"verified_execution_id,omitempty"`
	RejectionCode         string   `json:"rejection_code,omitempty"`
}

func rejected(req Request, code string, err error) Response {
	rationale := []string{"Signed evidence was rejected before verdict computation."}
	if err != nil {
		rationale = append(rationale, err.Error())
	}
	return Response{
		Accepted:             false,
		Decision:             "REJECTED",
		Rationale:            rationale,
		Authority:            "DETERMINISTIC_GO_GATEKEEPER",
		Component:            "release-sentinel-go-gatekeeper",
		LLMPresent:           false,
		AgentInfluence:       0,
		IgnoredAgentOpinions: len(req.AgentOpinions),
		EvidenceVerified:     false,
		RejectionCode:        code,
	}
}

func DecideVerified(req Request, verifier *Verifier) Response {
	if verifier == nil {
		return rejected(req, "TRUST_ROOT_UNAVAILABLE", fmt.Errorf("evidence verifier is not configured"))
	}
	bundle, code, err := verifier.Verify(req)
	if err != nil {
		return rejected(req, code, err)
	}

	highCritical := 0
	medium := 0
	for _, result := range bundle.Results {
		if !result.Failed || !result.BlockingEligible {
			continue
		}
		switch result.Severity {
		case "HIGH", "CRITICAL":
			highCritical++
		case "MEDIUM":
			medium++
		}
	}
	resp := Response{
		Accepted:              true,
		Authority:             "DETERMINISTIC_GO_GATEKEEPER",
		Component:             "release-sentinel-go-gatekeeper",
		LLMPresent:            false,
		AgentInfluence:        0,
		IgnoredAgentOpinions:  len(req.AgentOpinions),
		AuthoritativeBlockers: highCritical,
		AuthoritativeMedium:   medium,
		EvidenceVerified:      true,
		VerifiedExecutionID:   bundle.ExecutionID,
	}
	if highCritical > 0 {
		resp.Decision = "NO_GO"
		resp.Rationale = []string{
			fmt.Sprintf("%d high/critical finding(s) exist in cryptographically verified evidence.", highCritical),
			"Agent opinions were received but have zero decision authority.",
		}
		return resp
	}
	if medium > 0 {
		resp.Decision = "CONDITIONAL_GO"
		resp.Rationale = []string{fmt.Sprintf("%d verified medium-severity finding(s) remain.", medium)}
		return resp
	}
	resp.Decision = "GO"
	resp.Rationale = []string{"No blocking failure exists in the verified evidence bundle."}
	return resp
}
