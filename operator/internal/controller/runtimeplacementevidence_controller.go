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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
)

// RuntimePlacementEvidenceReconciler reconciles a RuntimePlacementEvidence object.
//
// RuntimePlacementEvidence is produced and fully populated (signed, with
// behavior counters and conformance verdict) by the node eBPF agent itself
// (Phase 4) — the Operator is not the source of truth for its content, and
// has nothing to compute here yet. This reconciler is registered now so the
// watch/informer wiring exists; Phase 4/6 may add operator-side aggregation
// (e.g. multi-node conformance rollups) once the agent produces real evidence
// to aggregate over.
type RuntimePlacementEvidenceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimeplacementevidences,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimeplacementevidences/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=aiops.imperium.io,resources=runtimeplacementevidences/finalizers,verbs=update

func (r *RuntimePlacementEvidenceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *RuntimePlacementEvidenceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&aiopsv1alpha1.RuntimePlacementEvidence{}).
		Complete(r)
}
