# Docker Multi-Backend - Estrutura Criada

## 📁 Estrutura de Arquivos

```
docker/
├── configs/                              # Exemplos de configuração
│   ├── cloudflare-r2.example.json       # Exemplo Cloudflare R2
│   ├── config.example.json              # Exemplo genérico S3
│   └── multi-provider.example.json      # Exemplo multi-provedor
├── .env.example                          # Template de variáveis de ambiente
├── .gitignore                            # Ignora credenciais e configs reais
├── docker-compose.yml                    # Orquestração Docker Compose
├── Dockerfile.multibackend               # Build da imagem multi-backend
├── entrypoint.sh                         # Script de entrada do container
├── quickstart.sh                         # Script de inicialização rápida
├── README.md                             # Documentação completa (inglês)
└── README.pt-BR.md                       # Documentação completa (português)
```

## 🎯 Funcionalidades Implementadas

### 1. Docker Compose Completo
- **Build automático** da imagem Go
- **Multi-stage build** (builder + runtime alpine)
- **Health checks** integrados
- **Auto-restart** em caso de falha
- **Network isolada** para o serviço

### 2. Configuração via Environment Variables

Todas as opções são configuráveis via `.env`:

| Variável | Propósito | Padrão |
|----------|-----------|--------|
| `VGW_CONFIG_FILE` | Caminho do config JSON | `/etc/versitygw/config.json` |
| `VGW_ACCESS_KEY` | Credencial do gateway | (auto-gerada) |
| `VGW_SECRET_KEY` | Secret do gateway | (auto-gerada) |
| `VGW_PORT` | Porta do servidor | `7070` |
| `VGW_HOST` | Host/endereço | `0.0.0.0` |
| `VGW_REGION` | Região AWS | `us-east-1` |
| `VGW_DEBUG` | Modo debug | `false` |
| `CONFIG_PATH` | Path host do config | `./configs/config.json` |

### 3. Exemplos de Configuração

#### A. Genérico S3 (`config.example.json`)
- Template básico para qualquer S3
- 2 backends de exemplo
- Comentários explicativos

#### B. Cloudflare R2 (`cloudflare-r2.example.json`)
- Configuração específica para R2
- **Região correta**: `us-east-1` (não "auto")
- Formato de endpoint R2
- Notas sobre credenciais R2

#### C. Multi-Provedor (`multi-provider.example.json`)
- AWS S3 + Cloudflare R2 + MinIO
- Casos de uso explicados
- Estratégia de fallback

### 4. Script de Quick Start

`quickstart.sh` automatiza:
- ✅ Verificação de Docker/Docker Compose
- ✅ Criação do arquivo `.env`
- ✅ Escolha interativa de config
- ✅ Configuração de credenciais (auto ou custom)
- ✅ Seleção de porta
- ✅ Modo debug opcional
- ✅ Build da imagem
- ✅ Start do serviço
- ✅ Exibição de instruções de uso

### 5. Entrypoint Inteligente

`entrypoint.sh` gerencia:
- ✅ Validação do binário
- ✅ Detecção automática de config
- ✅ Montagem de argumentos CLI
- ✅ Suporte a todas as flags do `s3multi`
- ✅ Mensagens de erro claras

### 6. Dockerfile Otimizado

`Dockerfile.multibackend`:
- ✅ Multi-stage build (reduz tamanho final)
- ✅ Build com Go 1.24 Alpine
- ✅ Runtime Alpine mínimo
- ✅ CA certificates inclusos (HTTPS)
- ✅ Build args para versionamento
- ✅ Healthcheck endpoint

### 7. Documentação Bilíngue

#### `README.md` (Inglês) - 340 linhas
- Quick start completo
- Tabela de env vars
- 5 exemplos práticos
- 3 exemplos de configuração
- Comandos Docker
- Troubleshooting
- Segurança
- Produção

#### `README.pt-BR.md` (Português) - 320 linhas
- Tradução completa
- Mesma estrutura
- Exemplos localizados

## 🚀 Como Usar

### Método 1: Quick Start (Recomendado)

```bash
cd docker
./quickstart.sh
```

O script vai:
1. Verificar dependências
2. Criar `.env`
3. Perguntar qual config usar
4. Configurar credenciais
5. Build e start automático
6. Exibir instruções

### Método 2: Manual

```bash
cd docker

# 1. Setup
cp .env.example .env
cp configs/cloudflare-r2.example.json configs/config.json

# 2. Editar configs
nano configs/config.json  # Adicionar credenciais backend
nano .env                 # Configurar variáveis (opcional)

# 3. Start
docker-compose up -d

# 4. Logs
docker-compose logs -f
```

### Método 3: One-liner para teste rápido

```bash
cd docker && \
  cp .env.example .env && \
  cp configs/cloudflare-r2.example.json configs/config.json && \
  docker-compose up -d && \
  docker-compose logs -f
```

## 🔐 Segurança

### Arquivos Protegidos (.gitignore)

```
.env                    # Nunca commitar credenciais
configs/config.json     # Config com credenciais reais
*.key, *.crt           # Certificados
logs/                  # Logs podem ter info sensível
```

### Credenciais Auto-Geradas

Se não configurar `VGW_ACCESS_KEY` e `VGW_SECRET_KEY`:
- Gateway gera credenciais aleatórias
- Usa `crypto/rand` (seguro)
- 20 chars (access) + 40 chars (secret)
- Exibidas no log na inicialização

## 📊 Recursos do Container

### Padrão
- **Porta**: 7070
- **Recursos**: Ilimitado

### Opcional (descomentar no docker-compose.yml)
```yaml
deploy:
  resources:
    limits:
      cpus: '2'
      memory: 2G
    reservations:
      cpus: '0.5'
      memory: 512M
```

## 🧪 Testing

### Health Check
```bash
# Automático a cada 30s
curl http://localhost:7070/

# Manual
docker-compose exec versitygw-multibackend wget -O- http://localhost:7070/
```

### AWS CLI
```bash
export AWS_ACCESS_KEY_ID=<gateway-key>
export AWS_SECRET_ACCESS_KEY=<gateway-secret>
export AWS_ENDPOINT_URL=http://localhost:7070
export AWS_DEFAULT_REGION=us-east-1

aws s3 ls
aws s3 cp test.txt s3://bucket/
aws s3 presign s3://bucket/test.txt
```

## 📈 Monitoramento

### Logs
```bash
# Tempo real
docker-compose logs -f

# Últimas 100 linhas
docker-compose logs --tail=100

# Apenas erros
docker-compose logs | grep ERROR
```

### Status
```bash
# Container status
docker-compose ps

# Resource usage
docker stats versitygw-multibackend

# Health status
docker inspect versitygw-multibackend | grep Health -A 10
```

## 🔄 Operações

### Start/Stop
```bash
docker-compose up -d      # Start
docker-compose down       # Stop
docker-compose restart    # Restart
```

### Rebuild
```bash
docker-compose build              # Normal
docker-compose build --no-cache   # Sem cache
docker-compose up -d --build      # Build + Start
```

### Cleanup
```bash
docker-compose down        # Remove containers
docker-compose down -v     # Remove containers + volumes
```

## 🎁 Benefícios

### Para Desenvolvimento
- ✅ Setup em < 2 minutos
- ✅ Credenciais auto-geradas
- ✅ Modo debug fácil
- ✅ Logs em tempo real
- ✅ Rebuild rápido

### Para Produção
- ✅ Image Alpine leve (~80MB)
- ✅ Health checks automáticos
- ✅ Auto-restart configurado
- ✅ Resource limits disponíveis
- ✅ TLS/HTTPS suportado
- ✅ Secrets via env vars ou Docker secrets

### Para DevOps
- ✅ Docker Compose padrão
- ✅ Variáveis de ambiente
- ✅ Configuração externa
- ✅ Logs estruturados
- ✅ Fácil integração CI/CD

## 📝 Próximos Passos (Futuro)

Possíveis melhorias:
- [ ] Kubernetes Helm chart
- [ ] Prometheus metrics export
- [ ] Grafana dashboard
- [ ] Docker Swarm stack
- [ ] Exemplo com Nginx reverse proxy
- [ ] Exemplo com Traefik
- [ ] Multi-architecture builds (ARM64)

## 🎯 Casos de Uso

### 1. Desenvolvimento Local
```bash
./quickstart.sh
# Credenciais auto-geradas
# Debug ativado
# Teste rápido
```

### 2. CI/CD Testing
```yaml
# .gitlab-ci.yml
test:
  services:
    - docker:dind
  script:
    - cd docker
    - docker-compose up -d
    - docker-compose exec -T versitygw-multibackend /tests/run.sh
```

### 3. Staging Environment
```bash
# .env
VGW_ACCESS_KEY=staging-access-key
VGW_SECRET_KEY=staging-secret-key
VGW_PORT=7070
VGW_DEBUG=true
CONFIG_PATH=./configs/staging-config.json
```

### 4. Production Deployment
```bash
# .env
VGW_ACCESS_KEY=${VAULT_ACCESS_KEY}
VGW_SECRET_KEY=${VAULT_SECRET_KEY}
VGW_CERT=/etc/ssl/certs/server.crt
VGW_KEY=/etc/ssl/private/server.key
VGW_DEBUG=false
CONFIG_PATH=./configs/production-config.json
```

## 📚 Arquivos de Referência

| Arquivo | Linhas | Propósito |
|---------|--------|-----------|
| `docker-compose.yml` | 70 | Orquestração |
| `Dockerfile.multibackend` | 35 | Build da imagem |
| `entrypoint.sh` | 80 | Container init |
| `quickstart.sh` | 170 | Setup interativo |
| `.env.example` | 40 | Template vars |
| `README.md` | 340 | Doc inglês |
| `README.pt-BR.md` | 320 | Doc português |
| `config.example.json` | 15 | Template S3 |
| `cloudflare-r2.example.json` | 25 | Template R2 |
| `multi-provider.example.json` | 30 | Template híbrido |
| `.gitignore` | 20 | Segurança |

**Total**: ~1,145 linhas de código + documentação

---

✅ Estrutura Docker completa e pronta para uso!
