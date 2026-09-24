#!/usr/bin/env bash
# One-time setup shared by all Experiment A (Task 04) runs: RBAC for test
# pods' launcher initContainer to read RuntimeSecurityPolicy, and a target
# service the workload container connects to as its "critical operation"
# (network egress Ω class).
set -euo pipefail
export KUBECONFIG="${KUBECONFIG:-${REPO_ROOT}/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"

kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: workloads
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: closure-test-runner
  namespace: workloads
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: closure-test-runner
  namespace: workloads
rules:
  - apiGroups: ["aiops.imperium.io"]
    resources: ["runtimesecuritypolicies"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: closure-test-runner
  namespace: workloads
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: closure-test-runner
subjects:
  - kind: ServiceAccount
    name: closure-test-runner
    namespace: workloads
---
apiVersion: v1
kind: Service
metadata:
  name: closure-target-svc
  namespace: workloads
spec:
  selector: { app: closure-target }
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: closure-target
  namespace: workloads
spec:
  replicas: 1
  selector:
    matchLabels: { app: closure-target }
  template:
    metadata:
      labels: { app: closure-target }
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports: [{ containerPort: 80 }]
EOF

kubectl -n workloads rollout status deployment/closure-target --timeout=120s
echo "setup complete"
