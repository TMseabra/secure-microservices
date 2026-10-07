# secure-microservices

Microserviços em Go com autorização separada e deploy seguro em Kubernetes. Projeto sobre segurança entre serviços: quem emite tokens, quem os valida e quem pode falar com quem.

> Estado: em planeamento (projeto de portefólio). Vem depois do [auth-api](https://github.com/TMseabra/auth-api) e do [auth-lab](https://github.com/TMseabra/auth-lab).

## Objetivo

Separar a emissão de identidade da proteção dos dados, e mostrar como se protege um sistema com vários serviços, do código ao cluster.

## Serviços (monorepo)

- auth-service: emite e renova tokens JWT
- api-service: dados protegidos; valida o JWT e aplica RBAC por papel
- gateway (opcional): ponto de entrada único

Cada serviço fica na sua pasta, com os manifestos Kubernetes e uma só pipeline com matriz de serviços.

## Stack

- Go
- Docker e docker-compose
- Kubernetes local (kind ou minikube)
- GitHub Actions, Dependabot e Trivy

## Plano

### Construir

1. auth-service e api-service a funcionar com docker-compose
2. api-service a validar o JWT e a aplicar RBAC por papel
3. gateway à frente dos serviços (opcional)

### Proteger

4. Dependabot e Trivy em todos os serviços (pipeline com matriz)
5. Deploy no cluster local com Kubernetes
6. Secrets do Kubernetes para as chaves
7. NetworkPolicy: só o gateway fala com o auth-service
8. Contentores sem root
9. Scan dos manifestos com trivy config

## Decisões de segurança

A preencher à medida que o projeto avança.

## Como correr

A preencher quando existir o docker-compose.

## Licença

MIT
