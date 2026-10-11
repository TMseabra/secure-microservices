#!/usr/bin/env sh
# Builds the images, loads them into a local kind cluster, creates the Secrets and applies the manifests.
set -eu

CLUSTER=${CLUSTER:-secure-microservices}
NS=secure-microservices

[ -f keys/private.pem ] || sh scripts/gen-keys.sh

# NetworkPolicy needs a CNI that enforces it (e.g. Calico/Cilium); the default kindnet may not.
kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER"

for svc in auth-service api-service gateway; do
  docker build -t "secure-microservices/$svc:local" "./$svc"
  kind load docker-image "secure-microservices/$svc:local" --name "$CLUSTER"
done

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -

# Secrets are created from local files and never committed. The private key goes only to the auth-service.
kubectl -n "$NS" create secret generic jwt-private-key --from-file=private.pem=keys/private.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic jwt-public-key --from-file=public.pem=keys/public.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "$NS" create secret generic auth-users \
  --from-literal=users="${AUTH_USERS:-alice:alice-pass:admin,bob:bob-pass:user}" \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl apply -f k8s/base.yaml -f k8s/network-policies.yaml
kubectl -n "$NS" rollout status deploy/auth-service deploy/api-service deploy/gateway
echo "try: kubectl -n $NS port-forward svc/gateway 8000:8000"
