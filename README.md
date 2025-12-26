# Task Manager API (Hardened)

API REST segura e pronta para produção em Rust (Actix-web).

## Features de Segurança & Produção

- **Autenticação JWT Forte**: Sem fallback inseguro, validação rigorosa (HS256, expiração).
- **Rate Limiting**: Proteção contra DdoS (configurável) via `actix-governor`.
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
3. Variáveis de Ambiente (prefixo `APP` com separador hierárquico `__`)

### Tabela de Configuração

| Categoria | Varável (YAML) | Varável (ENV) | Default | Descrição |
|---|---|---|---|---|
| Server | `server.host` | `APP__SERVER__HOST` | `0.0.0.0` | Endereço de bind |
| Server | `server.port` | `APP__SERVER__PORT` | `8081` | Porta do servidor |
| Database | `database.url` | `APP__DATABASE__URL` | `sqlite://tasks.db` | URL de conexão (ex: `sqlite://tasks.db`) |
| Security | `security.jwt_secret` | `APP__SECURITY__JWT_SECRET` | `""` | **OBRIGATÓRIO** Segredo JWT (mínimo 32 bytes) |
| Security | `security.enable_swagger` | `APP__SECURITY__ENABLE_SWAGGER` | `false` | Habilita Swagger UI (desabilitar em produção) |
| Rate Limit | `rate_limit.per_second` | `APP__RATE_LIMIT__PER_SECOND` | `10` | Requisições por segundo por IP |
| Rate Limit | `rate_limit.burst_size` | `APP__RATE_LIMIT__BURST_SIZE` | `20` | Píco máximo de requisições em burst |
| CORS | `cors.allowed_origin` | `APP__CORS__ALLOWED_ORIGIN` | `http://localhost:3000` | Origem permitida para CORS |
| Observability | `observability.log_level` | `APP__OBSERVABILITY__LOG_LEVEL` | `info` | Nível de log: `debug`, `info`, `warn`, `error` |
| observability | `observability.log_format` | `APP__OBSERVABILITY__LOG_FORMAT` | `json` | Formato de log: `json` ou `text` |
| observability | `observability.enable_metrics` | `APP__OBSERVABILITY__ENABLE_METRICS` | `true` | Habilita endpoint `/metrics` (Prometheus) |

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

rate_limit:
  per_second: 10         # Requisições por segundo por IP
  burst_size: 20         # Píco máximo de requisições em burst

cors:
  allowed_origin: "http://localhost:3000"  # Origem permitida para CORS

observability:
  log_level: "info"      # Nível de log: debug, info, warn, error
  log_format: "json"      # Formato: json ou text
  enable_metrics: true   # Habilita endpoint /metrics (Prometheus)
```

### Exemplo de Variáveis de Ambiente

```bash
# Segurança (Obrigatório)
export APP__SECURITY__JWT_SECRET="$(openssl rand -base64 64)"

# Server
export APP__SERVER__HOST="0.0.0.0"
export APP__SERVER__PORT=8081

# Database
export APP__DATABASE__URL="sqlite://tasks.db"

# Rate Limiting
export APP__RATE_LIMIT__PER_SECOND=50
export APP__RATE_LIMIT__BURST_SIZE=100

# CORS
export APP__CORS__ALLOWED_ORIGIN="https://myapp.com"

# Observability
export APP__OBSERVABILITY__LOG_LEVEL="debug"
export APP__OBSERVABILITY__LOG_FORMAT="text"
export APP__OBSERVABILITY__ENABLE_METRICSfalse
```

## Gerando Segredos Seguros

Para `guardar` ou `passar` o `JWT_SECRET`, gere uma string aleatória forte:

```bash
openssl rand -base64 64
# ou
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

## Execução

```bash
# 1. Setup (Migrations)
cargo sqlx migrate run

# 2. Rodar (Produção)
# Passando secret via ENV (recomendado)
APP__SECURITY__JWT_SECRET="$(openssl rand -base64 64)" cargo run --release

# 3. Rodar com configuração personalizada
APP__SERVER__PORT=9000 \
APP__RATE_LIMIT__PER_SECOND=50 \
APP__SECURITY__JWT_SECRET="$(openssl rand -base64 64)" \
cargo run --release
```

## Endpoints

- `GET /health`: Healthcheck
- `GET /metrics`: Métricas Prometheus (se habilitado)
- `POST /auth/register`: Registro de usuário
- `POST /auth/login`: Retorna JWT
- `GET /tasks`: Lista tarefas (Requer Auth)
- `GET /tasks/{id}`: Detalhes da tarefa (Requer Auth)
- `POST /tasks`: Cria tarefa (Requer Auth)
- `PUT /tasks/{id}`: Atualiza tarefa (Requer Auth)
- `DELETE /tasks/{id}`: Remove tarefa (Requer Auth)

## Swagger UI

Para habilitar em desenvolvimento:

```bash
APP__SECURITY__ENABLE_SWAGGER=true cargo run
```

Acesse: `/swagger-ui/`

## Exemplos de Uso

### 1. Rodar em Desenvolvimento com Swagger

```bash
APP__SECURITY__JWT_SECRET="my-dev-secret-12345678" \
APP__SECURITY__ENABLE_SWAGGER=true \
APP__OBSERVABILITY__LOG_LEVEL=debug \
APP__OBSERVABILITY__LOG_FORMAT=text \
cargo run
```

### 2. Rodar em Produção com Rate Limit Alto

```bash
APP__SECURITY__JWT_SECRET="$(openssl rand -base64 64)" \
APP__SERVER__PORT=8080 \
APP__RATE_LIMIT__PER_SECOND=100 \
APP__RATE_LIMIT__BURST_SIZE=200 \
APP__CORS__ALLOWED_ORIGIN="https://myapp.com" \
cargo run --release
```

### 3. Rodar com Métricas Desabilitadas

```bash
APP__SECURITY__JWT_SECRET="my-secret" \
APP__OBSERVABILITY__ENABLE_METRICS=false \
cargo run
```

## Segurança em Produção

1. **JWT Secret**: Use um secret forte e único (mínimo 32 bytes).
2. **CORS**: Configure `allowed_origin` para seu domínio real.
3. **Rate Limit**: Ajuste `per_second` e `burst_size` conforme a capacidade do seu servidor.
4. **Logs**: Use formato `json` em produção para integração com ELK/Datadog.
5. **Swagger**: Desabilite em produção (`enable_swagger: false`).

## Monitoramento

### Métricas Prometheus

Acesse `/metrics` para obter métricas no formato Prometheus:

```bash
curl http://localhost:8081/metrics
```

Exemplo de configuração Prometheus:

```yaml
scrape_configs:
  - job_name: 'task-manager-api'
    static_configs:
      - targets: ['localhost:8081']
```

### Logs Estruturados

Os logs são emitidos em formato JSON por padrão:

```json
{
  "timestamp": "2024-01-15T12:34:56Z",
  "level": "INFO",
  "fields": {
    "message": "Request completed",
    "method": "GET",
    "path": "/tasks",
    "status": 200,
    "duration_ms": 45
  }
}
```

## Licença

MIT License - veja `LICENSE` para detalhes.
