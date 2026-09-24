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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
)

// RuntimeSecurityPolicyReconciler reconciles a RuntimeSecurityPolicy object.
//
// At this stage (Phase 3, Operator only) it only acknowledges well-formed
// policy objects: CRD-level CEL/regex validation already rejects malformed
// specs at admission time, so there is little left to check before the node
// eBPF agent exists. Populating Status.AgentImageDigestVerified and
// Status.EvidenceMode from a real DaemonSet pod's running image digest is
// Phase 4 work — deliberately not stubbed out here, since there is no
// DaemonSet yet to check against and a half-built check against a
// non-existent resource would be worse than an honest gap. See
// EXPERIMENTS_LOG.md / DESIGN.md.
type RuntimeSecurityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimesecuritypolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimesecuritypolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimesecuritypolicies/finalizers,verbs=update

func (r *RuntimeSecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := r.Get(ctx, req.NamespacedName, &policy); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	policy.Status.ObservedGeneration = policy.Generation
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:    "Ready",
		Status:  metav1.ConditionTrue,
		Reason:  "PolicyAccepted",
		Message: "policy schema accepted; agent integrity/enforcement status pending node agent (Phase 4)",
	})
	if err := r.Status().Update(ctx, &policy); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuntimeSecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Complete(r)
}
