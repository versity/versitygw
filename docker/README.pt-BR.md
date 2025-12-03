# VersityGW Multi-Backend - Configuração Docker

Configuração completa em Docker Compose para executar o VersityGW em modo multi-backend com fallback automático.

## Funcionalidades

- 🐳 **Docker Compose** - Deploy fácil com um único comando
- ⚙️ **Variáveis de Ambiente** - Configure tudo via arquivo `.env`
- 🔐 **Credenciais Auto-Geradas** - Credenciais do gateway opcionalmente aleatórias
- 📝 **Múltiplos Exemplos** - AWS S3, Cloudflare R2, Multi-provedor
- 🔄 **Auto-Reinício** - Container reinicia automaticamente em caso de falha
- 💚 **Health Checks** - Monitoramento de saúde do container integrado
- 📊 **Limites de Recursos** - Constraints opcionais de CPU e memória

## Início Rápido

### 1. Copiar Arquivo de Ambiente

```bash
cd docker
cp .env.example .env
```

### 2. Criar Arquivo de Configuração

Escolha um dos exemplos de configuração:

```bash
# Para AWS S3
cp configs/config.example.json configs/config.json

# Para Cloudflare R2
cp configs/cloudflare-r2.example.json configs/config.json

# Para Multi-Provedor
cp configs/multi-provider.example.json configs/config.json
```

Edite `configs/config.json` com suas credenciais de backend.

### 3. Configurar Ambiente (Opcional)

Edite o arquivo `.env` para customizar:

```bash
# Porta do servidor
VGW_PORT=7070

# Credenciais do gateway (deixe vazio para auto-geração)
VGW_ACCESS_KEY=
VGW_SECRET_KEY=

# Caminho do arquivo de config
CONFIG_PATH=./configs/config.json

# Modo debug
VGW_DEBUG=false
```

### 4. Iniciar o Gateway

```bash
# Build e start
docker-compose up -d

# Ver logs
docker-compose logs -f

# Verificar status
docker-compose ps
```

### 5. Testar o Gateway

```bash
# Configurar AWS CLI
export AWS_ACCESS_KEY_ID=<gateway-access-key>
export AWS_SECRET_ACCESS_KEY=<gateway-secret-key>
export AWS_ENDPOINT_URL=http://localhost:7070
export AWS_DEFAULT_REGION=us-east-1

# Testar operações
aws s3 ls
aws s3 cp teste.txt s3://meu-bucket/
aws s3 ls s3://meu-bucket/

# Gerar URL pré-assinada (expiração padrão de 1 hora)
aws s3 presign s3://meu-bucket/teste.txt

# Gerar URL pré-assinada com expiração customizada (5 minutos)
aws s3 presign s3://meu-bucket/teste.txt --expires-in 300
```

## URLs Pré-Assinadas

### Definindo o Tempo de Expiração

O tempo de expiração das URLs pré-assinadas é definido pelo **CLIENTE** ao gerar a URL, não pelo gateway.

**Tempos de expiração comuns:**
```bash
# 5 minutos
aws s3 presign s3://bucket/arquivo.txt --expires-in 300

# 1 hora (padrão)
aws s3 presign s3://bucket/arquivo.txt --expires-in 3600

# 24 horas
aws s3 presign s3://bucket/arquivo.txt --expires-in 86400

# Máximo (7 dias)
aws s3 presign s3://bucket/arquivo.txt --expires-in 604800
```

**Limites validados pelo gateway:**
- Mínimo: 1 segundo
- Máximo: 7 dias (604800 segundos)
- Padrão: 1 hora (3600 segundos) se não especificado

**Nenhuma configuração no gateway necessária** - o cliente controla o tempo de expiração via parâmetro `--expires-in`.

## Opções de Configuração

### Variáveis de Ambiente

| Variável | Descrição | Padrão | Obrigatório |
|----------|-----------|--------|-------------|
| `VGW_CONFIG_FILE` | Caminho para config JSON dentro do container | `/etc/versitygw/config.json` | Sim (auto) |
| `VGW_ACCESS_KEY` | Access key do gateway para clientes | (auto-gerada) | Não |
| `VGW_SECRET_KEY` | Secret key do gateway para clientes | (auto-gerada) | Não |
| `VGW_PORT` | Porta do servidor | `7070` | Não |
| `VGW_HOST` | Host/endereço do servidor | `0.0.0.0` | Não |
| `VGW_REGION` | Região do gateway | `us-east-1` | Não |
| `VGW_DEBUG` | Ativar logging debug | `false` | Não |
| `CONFIG_PATH` | Caminho host para arquivo config | `./configs/config.json` | Sim |

### Arquivo de Configuração de Backends

O arquivo JSON define seus backends S3:

```json
{
  "backends": [
    {
      "name": "backend-primario",
      "access": "BACKEND_ACCESS_KEY",
      "secret": "BACKEND_SECRET_KEY",
      "endpoint": "https://s3.provedor.com/nome-bucket",
      "region": "us-east-1"
    },
    {
      "name": "backend-fallback",
      "access": "BACKEND_ACCESS_KEY",
      "secret": "BACKEND_SECRET_KEY",
      "endpoint": "https://s3.provedor.com/bucket-fallback",
      "region": "us-east-1"
    }
  ]
}
```

**Notas Importantes:**
- **Formato do endpoint**: Deve incluir nome do bucket no path (ex: `https://endpoint.com/nome-bucket`)
- **Cloudflare R2**: Sempre use `"region": "us-east-1"`, não `"auto"`
- **Credenciais**: São para acessar o storage backend, NÃO para clientes conectarem ao gateway

## Exemplos de Uso

### Exemplo 1: Credenciais do Gateway Auto-Geradas

```bash
# Não configure VGW_ACCESS_KEY e VGW_SECRET_KEY no .env
docker-compose up -d

# Verifique os logs para ver as credenciais geradas
docker-compose logs | grep "Generated random"
# Saída:
# ⚠️  Generated random ACCESS KEY: HLhzp7dJ6pOpKSzWfzoy
# ⚠️  Generated random SECRET KEY: jVde2GVT-wnZK1mc1FHX-2JCCJTtkXetnvAda-Kg
```

### Exemplo 2: Credenciais Customizadas

Edite `.env`:
```bash
VGW_ACCESS_KEY=minha-access-key-customizada
VGW_SECRET_KEY=minha-secret-key-customizada
```

```bash
docker-compose up -d
```

### Exemplo 3: Suporte HTTPS/TLS

Crie certificados:
```bash
mkdir -p certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key -out certs/server.crt
```

Edite `.env`:
```bash
VGW_CERT=/etc/versitygw/certs/server.crt
VGW_KEY=/etc/versitygw/certs/server.key
```

Descomente volume no `docker-compose.yml`:
```yaml
volumes:
  - ./certs:/etc/versitygw/certs:ro
```

```bash
docker-compose up -d
```

### Exemplo 4: Modo Debug

Edite `.env`:
```bash
VGW_DEBUG=true
```

```bash
docker-compose up -d
docker-compose logs -f  # Acompanhe logs detalhados
```

### Exemplo 5: Porta Diferente

Edite `.env`:
```bash
VGW_PORT=8080
```

```bash
docker-compose up -d
# Gateway agora disponível em http://localhost:8080
```

## Exemplos de Configuração

### Cloudflare R2 - Dois Buckets

`configs/config.json`:
```json
{
  "backends": [
    {
      "name": "r2-primario",
      "access": "abc123...",
      "secret": "xyz789...",
      "endpoint": "https://abc123.r2.cloudflarestorage.com/bucket-primario",
      "region": "us-east-1"
    },
    {
      "name": "r2-fallback",
      "access": "abc123...",
      "secret": "xyz789...",
      "endpoint": "https://abc123.r2.cloudflarestorage.com/bucket-fallback",
      "region": "us-east-1"
    }
  ]
}
```

### AWS S3 Multi-Região

`configs/config.json`:
```json
{
  "backends": [
    {
      "name": "s3-us-east",
      "access": "AWS_ACCESS_KEY",
      "secret": "AWS_SECRET_KEY",
      "endpoint": "https://s3.us-east-1.amazonaws.com/meu-bucket-east",
      "region": "us-east-1"
    },
    {
      "name": "s3-eu-west",
      "access": "AWS_ACCESS_KEY",
      "secret": "AWS_SECRET_KEY",
      "endpoint": "https://s3.eu-west-1.amazonaws.com/meu-bucket-eu",
      "region": "eu-west-1"
    }
  ]
}
```

### Multi-Provedor Híbrido

`configs/config.json`:
```json
{
  "backends": [
    {
      "name": "aws-primario",
      "access": "AWS_ACCESS_KEY",
      "secret": "AWS_SECRET_KEY",
      "endpoint": "https://s3.us-east-1.amazonaws.com/bucket-prod",
      "region": "us-east-1"
    },
    {
      "name": "r2-backup",
      "access": "R2_ACCESS_KEY",
      "secret": "R2_SECRET_KEY",
      "endpoint": "https://account.r2.cloudflarestorage.com/bucket-backup",
      "region": "us-east-1"
    },
    {
      "name": "minio-local",
      "access": "MINIO_ACCESS_KEY",
      "secret": "MINIO_SECRET_KEY",
      "endpoint": "https://minio.interno.empresa.com/bucket-arquivo",
      "region": "us-east-1"
    }
  ]
}
```

## Comandos Docker

### Operações Básicas

```bash
# Iniciar serviços
docker-compose up -d

# Parar serviços
docker-compose down

# Reiniciar serviços
docker-compose restart

# Ver logs
docker-compose logs -f

# Ver últimas 100 linhas de log
docker-compose logs --tail=100

# Verificar status
docker-compose ps

# Executar comando dentro do container
docker-compose exec versitygw-multibackend sh
```

### Rebuild da Imagem

```bash
# Rebuild após mudanças no código
docker-compose build

# Rebuild forçado sem cache
docker-compose build --no-cache

# Rebuild e restart
docker-compose up -d --build
```

### Gerenciamento de Recursos

```bash
# Ver uso de recursos
docker stats versitygw-multibackend

# Ver detalhes do container
docker inspect versitygw-multibackend

# Remover tudo (incluindo volumes)
docker-compose down -v
```

## Solução de Problemas

### Problema: Container reiniciando continuamente

Verifique os logs:
```bash
docker-compose logs versitygw-multibackend
```

Causas comuns:
- Caminho inválido do arquivo de config
- Credenciais de backend faltando
- JSON malformado no arquivo de config
- Porta já em uso

### Problema: Não consegue conectar ao backend

Ative modo debug:
```bash
# Edite .env
VGW_DEBUG=true

# Reinicie
docker-compose restart
docker-compose logs -f
```

### Problema: Health check falhando

Teste manualmente:
```bash
curl http://localhost:7070/
# ou
docker-compose exec versitygw-multibackend wget -O- http://localhost:7070/
```

### Problema: Arquivo de config não encontrado

Verifique o volume mount:
```bash
docker-compose exec versitygw-multibackend cat /etc/versitygw/config.json
```

## Boas Práticas de Segurança

1. **Nunca commite credenciais** - Use arquivo `.env` (já está no `.gitignore`)
2. **Use HTTPS/TLS** em produção - Monte certificados e configure `VGW_CERT`/`VGW_KEY`
3. **Rode credenciais** regularmente - Tanto do gateway quanto dos backends
4. **Limite recursos do container** - Descomente `deploy.resources` no `docker-compose.yml`
5. **Use gerenciamento de secrets** - Considere Docker secrets ou vaults externos para produção

## Recursos Adicionais

- [Documentação Principal](../README.pt-BR.md)
- [Guia Multi-Backend](../examples/README-s3-multi.pt-BR.md)
- [English Documentation](../README.md)
- [Exemplos de Configuração](./configs/)

## Suporte

Para problemas ou questões:
- GitHub Issues: https://github.com/versity/versitygw/issues
- Fork do Repositório: https://github.com/klaoslacerdacs/versitygw-multibackend
