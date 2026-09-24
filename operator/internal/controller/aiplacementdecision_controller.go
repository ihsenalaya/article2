/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/ed25519"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/internal/upstream"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

// AIPlacementDecisionReconciler reads article 1's AIPlacementDecision
// objects, verifies the Ed25519-signed placement token carried in their
// annotation against a trusted public key, and generates the corresponding
// RuntimeSecurityPolicy (article 2's enforcement contract for the node eBPF
// agent). It never writes to the AIPlacementDecision itself: article 2 does
// not own that CRD (see internal/upstream package doc).
type AIPlacementDecisionReconciler struct {
	client.Client

	// TrustAnchorNamespace/Name/Key locate the ConfigMap holding the
	// scheduler's Ed25519 public key (hex), per the DESIGN.md decision to
	// publish it as a plain ConfigMap rather than sharing article 1's
	// private-key Secret.
	TrustAnchorNamespace     string
	TrustAnchorConfigMapName string
	TrustAnchorConfigMapKey  string

	// AgentImageDigest is the pinned digest (repo@sha256:...) of the eBPF
	// agent DaemonSet image this Operator expects to be running (Janus-style
	// agent integrity requirement). Required — the reconciler refuses to
	// generate policies until it is set, rather than silently omitting the
	// integrity binding. Wired to a real value once Phase 4 builds the agent
	// image; see EXPERIMENTS_LOG.md.
	AgentImageDigest string
}

const (
	// ReasonMissingToken is used when the decision carries no placement token annotation.
	ReasonMissingToken = "MissingPlacementToken"
	// ReasonInvalidToken is used when the placement token fails verification.
	ReasonInvalidToken = "InvalidPlacementToken"
	// ReasonReplayDetected is used when a signed decision reuses monotonic state.
	ReasonReplayDetected = "ReplayDetected"
	// ReasonRollbackDetected is used when a signed decision regresses epoch/version state.
	ReasonRollbackDetected = "RollbackDetected"
	// ReasonDecisionRevoked is used when the upstream decision is explicitly revoked.
	ReasonDecisionRevoked = "DecisionRevoked"
	// ReasonUpstreamNotAllow is used when article 1 has not (yet, or ever) allowed this placement.
	ReasonUpstreamNotAllow = "UpstreamDecisionNotAllow"
	// ReasonTrustAnchorUnavailable is used when the scheduler's public key cannot be loaded.
	ReasonTrustAnchorUnavailable = "TrustAnchorUnavailable"
	// ReasonAgentImageDigestUnset is used when the Operator itself is missing required config.
	ReasonAgentImageDigestUnset = "AgentImageDigestUnset"
	// ReasonVerified marks a successfully verified, active policy.
	ReasonVerified = "Verified"
)

//+kubebuilder:rbac:groups=aiops.imperium.io,resources=aiplacementdecisions,verbs=get;list;watch
//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimesecuritypolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimesecuritypolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch

func (r *AIPlacementDecisionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := ctrl.LoggerFrom(ctx)

	var decision upstream.AIPlacementDecision
	if err := r.Get(ctx, req.NamespacedName, &decision); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// Typed clients do not populate TypeMeta on Get; set it explicitly so an
	// owner reference to this object carries a correct apiVersion/kind.
	decision.TypeMeta = metav1.TypeMeta{
		APIVersion: upstream.GroupVersion.String(),
		Kind:       "AIPlacementDecision",
	}

	if r.AgentImageDigest == "" {
		logger.Error(fmt.Errorf("AgentImageDigest is unset"),
			"refusing to generate RuntimeSecurityPolicy without a pinned agent image digest — Phase 4 must supply one")
		return ctrl.Result{}, nil
	}

	verdict, reason, verified, conditionReason := r.evaluate(ctx, &decision)

	policy := &aiopsv1alpha1.RuntimeSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      decision.Name,
			Namespace: decision.Namespace,
		},
	}

	result, err := controllerutil.CreateOrUpdate(ctx, r.Client, policy, func() error {
		if err := controllerutil.SetControllerReference(&decision, policy, r.Scheme()); err != nil {
			return fmt.Errorf("set owner reference: %w", err)
		}

		spec, err := r.derivePolicySpec(&decision, verified)
		if err != nil {
			return err
		}
		policy.Spec = spec
		return nil
	})
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("create or update RuntimeSecurityPolicy: %w", err)
	}
	if result != controllerutil.OperationResultNone {
		logger.Info("reconciled RuntimeSecurityPolicy", "name", policy.Name, "namespace", policy.Namespace, "result", result)
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if err := r.Get(ctx, types.NamespacedName{Name: policy.Name, Namespace: policy.Namespace}, policy); err != nil {
			return err
		}
		policy.Status.ObservedGeneration = policy.Generation
		switch verdict {
		case verdictActive:
			policy.Status.Decision = "active"
			policy.Status.RejectionReason = ""
			policy.Status.VerificationStatus = aiopsv1alpha1.VerificationStatusVerified
			meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
				Type:    "Verified",
				Status:  metav1.ConditionTrue,
				Reason:  ReasonVerified,
				Message: "placement token verified against trust anchor",
			})
		case verdictPending:
			policy.Status.Decision = "pending"
			policy.Status.RejectionReason = reason
			policy.Status.VerificationStatus = aiopsv1alpha1.VerificationStatusUnavailable
			meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
				Type:    "Verified",
				Status:  metav1.ConditionUnknown,
				Reason:  ReasonUpstreamNotAllow,
				Message: reason,
			})
		default: // verdictRejected
			policy.Status.Decision = "rejected"
			policy.Status.RejectionReason = reason
			policy.Status.VerificationStatus = aiopsv1alpha1.VerificationStatusFailed
			if conditionReason == "" {
				conditionReason = ReasonInvalidToken
			}
			meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
				Type:    "Verified",
				Status:  metav1.ConditionFalse,
				Reason:  conditionReason,
				Message: reason,
			})
		}
		return r.Status().Update(ctx, policy)
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("update RuntimeSecurityPolicy status: %w", err)
	}

	return ctrl.Result{}, nil
}

type verdict int

const (
	verdictRejected verdict = iota
	verdictPending
	verdictActive
)

// evaluate verifies the placement token annotation against the trust anchor
// and returns the resulting verdict, a human-readable reason (empty on
// success), and the binding fields to copy into the RuntimeSecurityPolicy
// spec (nil unless verification succeeded).
func (r *AIPlacementDecisionReconciler) evaluate(ctx context.Context, decision *upstream.AIPlacementDecision) (verdict, string, *verifiedDecision, string) {
	if decision.Status.Decision == "" {
		return verdictPending, "upstream AIPlacementDecision has not reached a decision yet", nil, ReasonUpstreamNotAllow
	}
	if decision.Status.Decision == "revoked" {
		return verdictRejected, "upstream AIPlacementDecision is revoked", nil, ReasonDecisionRevoked
	}
	if decision.Status.Decision != "allow" {
		return verdictRejected, fmt.Sprintf("upstream AIPlacementDecision status.decision=%q", decision.Status.Decision), nil, ReasonUpstreamNotAllow
	}

	raw, ok := decision.Annotations[placementtoken.AnnotationKey]
	if !ok || raw == "" {
		return verdictRejected, "missing " + placementtoken.AnnotationKey + " annotation", nil, ReasonMissingToken
	}

	tok, err := placementtoken.Decode(raw)
	if err != nil {
		return verdictRejected, fmt.Sprintf("decode placement token: %v", err), nil, ReasonInvalidToken
	}

	pub, err := r.loadTrustAnchor(ctx)
	if err != nil {
		return verdictRejected, fmt.Sprintf("load trust anchor public key: %v", err), nil, ReasonTrustAnchorUnavailable
	}

	if err := placementtoken.Verify(pub, tok); err != nil {
		return verdictRejected, fmt.Sprintf("verify placement token: %v", err), nil, ReasonInvalidToken
	}

	if err := r.reserveDecision(ctx, decision, tok.Payload); err != nil {
		reason := ReasonReplayDetected
		if isRollbackError(err) {
			reason = ReasonRollbackDetected
		}
		return verdictRejected, err.Error(), nil, reason
	}

	return verdictActive, "", &verifiedDecision{
		Token: tok,
		Binding: aiopsv1alpha1.PlacementBinding{
			DecisionID:      tok.Payload.DecisionID,
			DecisionVersion: tok.Payload.DecisionVersion,
			DecisionEpoch:   tok.Payload.DecisionEpoch,
			DecisionNonce:   tok.Payload.DecisionNonce,
			PodUID:          tok.Payload.PodUID,
			PodSpecHash:     tok.Payload.PodSpecHash,
			ImageDigest:     tok.Payload.ImageDigest,
			ModelDigest:     tok.Payload.ModelDigest,
			NodeIdentity:    tok.Payload.NodeIdentity,
			RuntimeClass:    tok.Payload.RuntimeClass,
		},
	}, ReasonVerified
}

// loadTrustAnchor reads the scheduler's Ed25519 public key from the
// configured ConfigMap on every reconcile (rather than caching it at
// startup) so key rotation does not require an Operator restart.
func (r *AIPlacementDecisionReconciler) loadTrustAnchor(ctx context.Context) (ed25519.PublicKey, error) {
	var cm corev1.ConfigMap
	key := types.NamespacedName{Namespace: r.TrustAnchorNamespace, Name: r.TrustAnchorConfigMapName}
	if err := r.Get(ctx, key, &cm); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("trust anchor configmap %s/%s not found", key.Namespace, key.Name)
		}
		return nil, err
	}
	hexKey, ok := cm.Data[r.TrustAnchorConfigMapKey]
	if !ok || hexKey == "" {
		return nil, fmt.Errorf("configmap %s/%s missing key %q", key.Namespace, key.Name, r.TrustAnchorConfigMapKey)
	}
	return platformcrypto.PubKeyFromHex(hexKey)
}

func (r *AIPlacementDecisionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&upstream.AIPlacementDecision{}).
		Complete(r)
}
