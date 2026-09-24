package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ihsenalaya/runtime-guard-operator/internal/upstream"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

const DecisionLedgerConfigMapName = "runtime-guard-decision-ledger"

var errDecisionRollback = errors.New("decision rollback detected")

type decisionLedgerEntry struct {
	DecisionID        string `json:"decisionID"`
	DecisionVersion   int64  `json:"decisionVersion"`
	DecisionEpoch     int64  `json:"decisionEpoch"`
	DecisionNonce     string `json:"decisionNonce"`
	SourceNamespace   string `json:"sourceNamespace"`
	SourceName        string `json:"sourceName"`
	SourceUID         string `json:"sourceUID,omitempty"`
	LastAcceptedAtUTC string `json:"lastAcceptedAtUTC"`
}

func (r *AIPlacementDecisionReconciler) reserveDecision(ctx context.Context, decision *upstream.AIPlacementDecision, payload placementtoken.Payload) error {
	ledger := &corev1.ConfigMap{}
	ledgerKey := types.NamespacedName{Namespace: r.TrustAnchorNamespace, Name: DecisionLedgerConfigMapName}
	if err := r.Get(ctx, ledgerKey, ledger); err != nil {
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("load decision ledger: %w", err)
		}
		ledger = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      DecisionLedgerConfigMapName,
				Namespace: r.TrustAnchorNamespace,
			},
			Data: map[string]string{},
		}
	}
	if ledger.Data == nil {
		ledger.Data = map[string]string{}
	}

	entryKey := decisionLedgerKey(payload.DecisionID)
	sourceNamespace := decision.Namespace
	sourceName := decision.Name
	sourceUID := string(decision.UID)

	if rawEntry := ledger.Data[entryKey]; rawEntry != "" {
		var existing decisionLedgerEntry
		if err := json.Unmarshal([]byte(rawEntry), &existing); err != nil {
			return fmt.Errorf("decode decision ledger entry: %w", err)
		}
		sameSource := existing.SourceNamespace == sourceNamespace && existing.SourceName == sourceName
		if existing.SourceUID != "" && sourceUID != "" {
			sameSource = sameSource && existing.SourceUID == sourceUID
		}
		if payload.DecisionEpoch < existing.DecisionEpoch ||
			(payload.DecisionEpoch == existing.DecisionEpoch && payload.DecisionVersion < existing.DecisionVersion) {
			return fmt.Errorf("%w: decision_id=%s incoming epoch/version=%d/%d existing epoch/version=%d/%d",
				errDecisionRollback, payload.DecisionID, payload.DecisionEpoch, payload.DecisionVersion,
				existing.DecisionEpoch, existing.DecisionVersion)
		}
		if payload.DecisionEpoch == existing.DecisionEpoch && payload.DecisionVersion == existing.DecisionVersion {
			if sameSource && payload.DecisionNonce == existing.DecisionNonce {
				return nil
			}
			return fmt.Errorf("decision replay detected: decision_id=%s epoch/version=%d/%d nonce=%s already recorded for %s/%s",
				payload.DecisionID, payload.DecisionEpoch, payload.DecisionVersion, payload.DecisionNonce,
				existing.SourceNamespace, existing.SourceName)
		}
		if payload.DecisionNonce == existing.DecisionNonce {
			return fmt.Errorf("decision nonce replay detected: decision_id=%s nonce=%s already recorded", payload.DecisionID, payload.DecisionNonce)
		}
	}

	entry := decisionLedgerEntry{
		DecisionID:        payload.DecisionID,
		DecisionVersion:   payload.DecisionVersion,
		DecisionEpoch:     payload.DecisionEpoch,
		DecisionNonce:     payload.DecisionNonce,
		SourceNamespace:   sourceNamespace,
		SourceName:        sourceName,
		SourceUID:         sourceUID,
		LastAcceptedAtUTC: metav1.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	rawEntry, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("encode decision ledger entry: %w", err)
	}
	ledger.Data[entryKey] = string(rawEntry)

	if ledger.ResourceVersion == "" {
		if err := r.Create(ctx, ledger); err != nil {
			return fmt.Errorf("create decision ledger: %w", err)
		}
		return nil
	}
	if err := r.Update(ctx, ledger); err != nil {
		return fmt.Errorf("update decision ledger: %w", err)
	}
	return nil
}

func decisionLedgerKey(decisionID string) string {
	return "decision." + platformcrypto.SHA256Hex([]byte(decisionID))
}

func isRollbackError(err error) bool {
	return errors.Is(err, errDecisionRollback)
}
