package evidence

import (
	"crypto/ed25519"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
)

const SchemaVersion = "runtime-placement-evidence/v1"

type Payload struct {
	SchemaVersion       string           `json:"schema_version"`
	PolicyRefName       string           `json:"policy_ref_name"`
	PolicyRefNamespace  string           `json:"policy_ref_namespace"`
	TargetRefName       string           `json:"target_ref_name"`
	TargetRefNamespace  string           `json:"target_ref_namespace"`
	DecisionID          string           `json:"decision_id"`
	DecisionHash        string           `json:"decision_hash"`
	PolicyHash          string           `json:"policy_hash"`
	PolicyGeneration    int64            `json:"policy_generation"`
	MonitorID           string           `json:"monitor_id"`
	NodeName            string           `json:"node_name"`
	PodUID              string           `json:"pod_uid"`
	CgroupID            string           `json:"cgroup_id"`
	Conformance         string           `json:"conformance"`
	EvidenceMode        string           `json:"evidence_mode"`
	AgentImageDigest    string           `json:"agent_image_digest"`
	AgentDigestVerified bool             `json:"agent_digest_verified"`
	Behavior            BehaviorCounters `json:"behavior"`
	EvidenceSequence    int64            `json:"evidence_sequence"`
	PreviousDigest      string           `json:"previous_evidence_digest,omitempty"`
	// DropCount, EventsDroppedSinceLastEvidence, MonitorEpoch,
	// LastHeartbeat, and HookSetDigest are part of the SIGNED payload
	// (Task 05, B1/B3) -- these are trust-relevant claims a verifier must
	// actually evaluate (experiment protocol: "do not add fields merely
	// decoratively"), not informational-only.
	DropCount                      int64  `json:"drop_count"`
	EventsDroppedSinceLastEvidence int64  `json:"events_dropped_since_last_evidence"`
	MonitorEpoch                   string `json:"monitor_epoch"`
	LastHeartbeat                  int64  `json:"last_heartbeat"`
	HookSetDigest                  string `json:"hook_set_digest"`
	// RevokedAtUnix, AuthorizationState, and LastAuthorizationSyncUnix are
	// part of the SIGNED payload as of Task 06/C4 (RevokedAt was
	// previously status-only/unsigned). RevokedAtUnix is 0 when not
	// revoked; AuthorizationState is the authoritative disambiguator so 0
	// is never itself read as "revoked at the Unix epoch."
	RevokedAtUnix             int64  `json:"revoked_at_unix,omitempty"`
	AuthorizationState        string `json:"authorization_state"`
	LastAuthorizationSyncUnix int64  `json:"last_authorization_sync_unix"`
	IssuedAt                  int64  `json:"issued_at"`
	ExpiresAt                 int64  `json:"expires_at"`
}

type BehaviorCounters struct {
	ExecAllowed         int64 `json:"exec_allowed"`
	ExecDenied          int64 `json:"exec_denied"`
	FileOpenAllowed     int64 `json:"file_open_allowed"`
	FileOpenDenied      int64 `json:"file_open_denied"`
	ConnectAllowed      int64 `json:"connect_allowed"`
	ConnectDenied       int64 `json:"connect_denied"`
	DeviceAccessAllowed int64 `json:"device_access_allowed"`
	DeviceAccessDenied  int64 `json:"device_access_denied"`
}

type Signature struct {
	Algorithm     string
	KeyIdentifier string
	PayloadDigest string
	SignatureHex  string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

func Sign(priv ed25519.PrivateKey, keyIdentifier string, payload Payload) (Signature, error) {
	if priv == nil {
		return Signature{}, fmt.Errorf("private key is nil")
	}
	if payload.SchemaVersion == "" {
		payload.SchemaVersion = SchemaVersion
	}
	canonical, err := platformcrypto.CanonicalJSON(payload)
	if err != nil {
		return Signature{}, fmt.Errorf("canonicalize payload: %w", err)
	}
	digest := platformcrypto.SHA256Hex(canonical)
	sigHex := platformcrypto.Ed25519Sign(priv, canonical)

	return Signature{
		Algorithm:     "ed25519",
		KeyIdentifier: keyIdentifier,
		PayloadDigest: digest,
		SignatureHex:  sigHex,
		IssuedAt:      time.Unix(payload.IssuedAt, 0).UTC(),
		ExpiresAt:     time.Unix(payload.ExpiresAt, 0).UTC(),
	}, nil
}

func Verify(pub ed25519.PublicKey, payload Payload, sig Signature) error {
	if pub == nil {
		return fmt.Errorf("public key is nil")
	}
	if payload.SchemaVersion == "" {
		payload.SchemaVersion = SchemaVersion
	}
	canonical, err := platformcrypto.CanonicalJSON(payload)
	if err != nil {
		return fmt.Errorf("canonicalize payload: %w", err)
	}
	digest := platformcrypto.SHA256Hex(canonical)
	if digest != sig.PayloadDigest {
		return fmt.Errorf("payload digest mismatch: payload hashes to %s, signature claims %s", digest, sig.PayloadDigest)
	}
	ok, err := platformcrypto.Ed25519Verify(pub, canonical, sig.SignatureHex)
	if err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("signature invalid")
	}
	return nil
}

func PayloadFromObject(obj *aiopsv1alpha1.RuntimePlacementEvidence) Payload {
	if obj == nil {
		return Payload{}
	}
	return Payload{
		SchemaVersion:       SchemaVersion,
		PolicyRefName:       obj.Spec.PolicyRef.Name,
		PolicyRefNamespace:  obj.Spec.PolicyRef.Namespace,
		TargetRefName:       obj.Spec.TargetRef.Name,
		TargetRefNamespace:  obj.Spec.TargetRef.Namespace,
		DecisionID:          obj.Status.DecisionID,
		DecisionHash:        obj.Status.DecisionHash,
		PolicyHash:          obj.Status.PolicyHash,
		PolicyGeneration:    obj.Status.PolicyGeneration,
		MonitorID:           obj.Status.MonitorID,
		NodeName:            obj.Spec.NodeName,
		PodUID:              obj.Status.PodUID,
		CgroupID:            obj.Status.CgroupID,
		Conformance:         obj.Status.Conformance,
		EvidenceMode:        string(obj.Status.EvidenceMode),
		AgentImageDigest:    obj.Status.AgentIntegrity.ImageDigest,
		AgentDigestVerified: obj.Status.AgentIntegrity.DigestVerified,
		Behavior: BehaviorCounters{
			ExecAllowed:         obj.Status.Behavior.ExecAllowed,
			ExecDenied:          obj.Status.Behavior.ExecDenied,
			FileOpenAllowed:     obj.Status.Behavior.FileOpenAllowed,
			FileOpenDenied:      obj.Status.Behavior.FileOpenDenied,
			ConnectAllowed:      obj.Status.Behavior.ConnectAllowed,
			ConnectDenied:       obj.Status.Behavior.ConnectDenied,
			DeviceAccessAllowed: obj.Status.Behavior.DeviceAccessAllowed,
			DeviceAccessDenied:  obj.Status.Behavior.DeviceAccessDenied,
		},
		EvidenceSequence:               obj.Status.EvidenceSequence,
		PreviousDigest:                 obj.Status.PreviousEvidenceDigest,
		DropCount:                      obj.Status.DropCount,
		EventsDroppedSinceLastEvidence: obj.Status.EventsDroppedSinceLastEvidence,
		MonitorEpoch:                   obj.Status.MonitorEpoch,
		LastHeartbeat:                  obj.Status.LastHeartbeat.Time.UTC().Unix(),
		HookSetDigest:                  obj.Status.HookSetDigest,
		RevokedAtUnix:                  revokedAtUnix(obj.Status.RevokedAt),
		AuthorizationState:             obj.Status.AuthorizationState,
		LastAuthorizationSyncUnix:      obj.Status.LastAuthorizationSync.Time.UTC().Unix(),
		IssuedAt:                       obj.Status.Signature.IssuedAt.Time.UTC().Unix(),
		ExpiresAt:                      obj.Status.Signature.ExpiresAt.Time.UTC().Unix(),
	}
}

func revokedAtUnix(t *metav1.Time) int64 {
	if t == nil || t.IsZero() {
		return 0
	}
	return t.Time.UTC().Unix()
}

func SignatureFromObject(obj *aiopsv1alpha1.RuntimePlacementEvidence) Signature {
	if obj == nil {
		return Signature{}
	}
	return Signature{
		Algorithm:     obj.Status.Signature.Algorithm,
		KeyIdentifier: obj.Status.Signature.KeyIdentifier,
		PayloadDigest: obj.Status.Signature.PayloadDigest,
		SignatureHex:  obj.Status.Signature.Signature,
		IssuedAt:      obj.Status.Signature.IssuedAt.Time.UTC(),
		ExpiresAt:     obj.Status.Signature.ExpiresAt.Time.UTC(),
	}
}
