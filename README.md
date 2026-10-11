# secure-microservices

Go microservices with separated authorization and a secure Kubernetes deployment. A project about security between services: who issues tokens, who validates them and who is allowed to talk to whom.

> Status: implemented, Kubernetes part not yet tested on a live cluster (portfolio project). Comes after [auth-api](https://github.com/TMseabra/auth-api) and [auth-lab](https://github.com/TMseabra/auth-lab).

## Goal

Separate identity issuance from data protection, and show how to secure a multi-service system from the code to the cluster.

## Services (monorepo)

- auth-service: issues and refreshes JWT tokens
- api-service: protected data; validates the JWT and enforces role-based access control (RBAC)
- gateway (optional): single entry point

Each service lives in its own folder, with its Kubernetes manifests and a single pipeline with a service matrix.

## Stack

- Go
- Docker and docker-compose
- Local Kubernetes (kind or minikube)
- GitHub Actions, Dependabot and Trivy

## Plan

### Build

1. auth-service and api-service running with docker-compose
2. api-service validating the JWT and enforcing RBAC by role
3. gateway in front of the services (optional)

### Secure

4. Dependabot and Trivy on every service (matrix pipeline)
5. Deploy to a local cluster with Kubernetes
6. Kubernetes Secrets for the keys
7. NetworkPolicy: only the gateway can talk to the auth-service
8. Non-root containers
9. Scan the manifests with trivy config

## Security decisions

- RS256 (asymmetric) JWTs: only the auth-service holds the private key; the api-service gets just the public key, so a compromised api-service cannot mint tokens.
- The api-service pins the algorithm to RS256 and checks `iss`, `aud` and `exp`, which blocks `alg: none` and algorithm-confusion attacks.
- RBAC by the `role` claim: `GET /items` allows `user` and `admin`, `POST /items` allows only `admin`.
- Short-lived access tokens (15 min) and single-use refresh tokens that rotate on every refresh. Refresh tokens are kept in memory, so they are lost on restart; a real deployment would use a store.
- Passwords are hashed with bcrypt, and unknown users cost the same time as wrong passwords.
- The gateway exposes only `/auth/login`, `/auth/refresh` and `/api/*`. In compose only the gateway publishes a port.
- Containers run as non-root (distroless `nonroot`), with a read-only filesystem, all capabilities dropped and no privilege escalation.
- Kubernetes: the namespace enforces the `restricted` Pod Security level, keys live in Secrets (never committed), and NetworkPolicies deny all ingress except gateway to auth-service and gateway to api-service.
- CI runs `go vet`, builds each image and scans it with Trivy (fails on HIGH/CRITICAL), and runs `trivy config` on the Dockerfiles and manifests. Dependabot covers Go modules, Dockerfiles and Actions.
- Users come from the `AUTH_USERS` env var (`name:password:role,...`). The defaults in compose are demo credentials only.

## How to run

### docker-compose

```sh
sh scripts/gen-keys.sh        # creates keys/ (git-ignored)
docker compose up --build

TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -d '{"username":"alice","password":"alice-pass"}' | sed 's/.*"access_token":"\([^"]*\)".*/\1/')
curl -H "Authorization: Bearer $TOKEN" localhost:8000/api/items
curl -X POST -H "Authorization: Bearer $TOKEN" localhost:8000/api/items   # admin only
```

Demo users: `alice` (admin) and `bob` (user), see `AUTH_USERS`.

### Kubernetes (kind)

Requires `kind`, `kubectl` and Docker. NetworkPolicy is only enforced if the cluster CNI supports it (for example Calico or Cilium; kind's default CNI does not).

```sh
sh scripts/k8s-deploy.sh
kubectl -n secure-microservices port-forward svc/gateway 8000:8000
```

The Kubernetes deployment has not been run end to end yet: `kind` was not available where this was built, so the manifests were only scanned with `trivy config`.

## License

MIT
