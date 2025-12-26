# Task Manager API (Hardened)

API REST segura e pronta para produção em Rust (Actix-web).

## Features de Segurança & Produção

- **Autenticação JWT Forte**: Sem fallback inseguro, validação rigorosa (HS256, expiração).
- **Rate Limiting**: Proteção contra DDoS (10 req/s por IP) via `actix-governor`.
- **Observabilidade**:
  - **Logs JSON**: Estruturados para ingestão (ELK/Datadog) via `tracing`.
  - **Métricas**: Endpoint `/metrics` (Prometheus).
  - **Tracing**: Instrumentação ponta a ponta (Request -> DB).
- **Segurança HTTP**: Headers (HSTS, XSS, Frame-Options) e CORS restritivo.
- **Configuração Flexível**: Via arquivo `config.yaml` ou variáveis de ambiente.

## Configuração

A aplicação carrega configurações nesta ordem (prioridade crescente):
1. `config.yaml` (raiz)
2. `config.{STAGE}.yaml` (onde STAGE é definido por `RUN_MODE`, ex: `development`, `production`)
3. Variáveis de Ambiente (prefixo `APP_`)

### Tabela de Configuração

| Categoria | Varável (YAML) | Varável (ENV) | Default | Descrição |
|---|---|---|---|---|
| Server | `server.host` | `APP_SERVER_HOST` | `0.0.0.0` | Endereço de bind |
| Server | `server.port` | `APP_SERVER_PORT` | `8081` | Porta do servidor |
| Database | `database.url` | `APP_DATABASE_URL` | `null` | URL de conexão (ex: `sqlite://tasks.db`) |
| Security | `security.jwt_secret` | `APP_SECURITY_JWT_SECRET` | `"` | **OBRIGATÓRIO** Segredo JWT |
| Security | `security.enable_swagger` | `APP_SECURITY_ENABLE_SWAGGER` | `false` | Habilita Swagger UI |

### Exemplo `config.yaml`

```yaml
server:
  host: "0.0.0.0"
  port: 8081

database:
  url: "sqlite://tasks.db"

security:
  jwt_secret: "" # Preencha ou use ENV para maior segurança
  enable_swagger: false
```

## Gerando Segredos Seguros

Para `guardar ou passar o `JWT_SECRET`, gere uma string aleatória forte:

```bash
openssl rand -base64 64
# ou
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

## Execuç÷o

```bash
# 1. Setup (Migrations)
cargo sqlx migrate run

# 2. Rodar (Produção)
# Passando secret via ENV (recomendado)
APP_SECURITY_JWT_SECRET="$(openssl rand -base64 64)" cargo run --release
```

## Endpoints

- `GET /health`: Healthcheck
- `GET /metrics`: Métricas Prometheus
- `POST /auth/login`: Retorna JWT
- `GET /tasks`: Lista tarefas (Requer Auth)
- ... (ver Swagger em dev)

## Swagger UI

Para habilitar em desenvolvimento:
```bash
APP_SECURITY_ENABLE_SWAGGER=true cargo run
```
Acesse: `/swagger-ui/`
