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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
)

var _ = Describe("RuntimeSecurityPolicy Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default", // TODO(user):Modify as needed
		}
		runtimesecuritypolicy := &aiopsv1alpha1.RuntimeSecurityPolicy{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind RuntimeSecurityPolicy")
			err := k8sClient.Get(ctx, typeNamespacedName, runtimesecuritypolicy)
			if err != nil && errors.IsNotFound(err) {
				resource := &aiopsv1alpha1.RuntimeSecurityPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: aiopsv1alpha1.RuntimeSecurityPolicySpec{
						PlacementDecisionRef: aiopsv1alpha1.ObjectReference{Name: "decision-1"},
						TargetRef:            aiopsv1alpha1.ObjectReference{Name: "workload-1"},
						EnforcementMode:      "audit",
						Exec:                 aiopsv1alpha1.ExecPolicy{DefaultAction: "deny"},
						FileAccess:           aiopsv1alpha1.FileAccessPolicy{DefaultAction: "deny"},
						NetworkEgress:        aiopsv1alpha1.NetworkEgressPolicy{DefaultAction: "deny"},
						DeviceAccess:         aiopsv1alpha1.DeviceAccessPolicy{DefaultAction: "deny"},
						AgentIntegrity: aiopsv1alpha1.AgentIntegritySpec{
							ExpectedImageDigest: "example.com/runtime-guard-ebpf-agent@sha256:" +
								"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			// TODO(user): Cleanup logic after each test, like removing the resource instance.
			resource := &aiopsv1alpha1.RuntimeSecurityPolicy{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance RuntimeSecurityPolicy")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &RuntimeSecurityPolicyReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())
			// TODO(user): Add more specific assertions depending on your controller's reconciliation logic.
			// Example: If you expect a certain status condition after reconciliation, verify it here.
		})
	})
})
