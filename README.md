# secure-microservices

Go microservices with separated authorization and a secure Kubernetes deployment. A project about security between services: who issues tokens, who validates them and who is allowed to talk to whom.

> Status: planning (portfolio project). Comes after [auth-api](https://github.com/TMseabra/auth-api) and [auth-lab](https://github.com/TMseabra/auth-lab).

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

To be filled in as the project progresses.

## How to run

To be filled in once docker-compose exists.

## License

MIT
