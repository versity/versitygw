# Exemplo de Configuração S3 Multi-Backend

**[English](README-s3-multi.md)** | **Português**

Este diretório contém exemplos de configuração para executar o VersityGW com múltiplos backends S3 para suporte a fallback.

## Arquivo de Configuração: s3-multi-config.json

O arquivo de configuração define múltiplos backends S3. O primeiro backend é o primário (usado para escritas), e os backends subsequentes são usados como fallbacks para operações de leitura.

## Uso

### Uso Básico

```bash
# Credenciais do gateway serão geradas aleatoriamente se não forem fornecidas
versitygw s3-multi --config examples/s3-multi-config.json --port :7070

# Ou especifique suas próprias credenciais do gateway
versitygw s3-multi \
  --config examples/s3-multi-config.json \
  --access ROOT_ACCESS_KEY \
  --secret ROOT_SECRET_KEY \
  --port :7070
```

**Nota:** Se você não fornecer `--access` e `--secret`, o VersityGW gerará automaticamente credenciais aleatórias e as exibirá na inicialização. Essas são as credenciais que os clientes S3 usarão para conectar ao gateway (não devem ser confundidas com as credenciais dos backends no arquivo de configuração).

### Com Variáveis de Ambiente

Você pode sobrescrever valores de configuração usando variáveis de ambiente:

```bash
export VGW_S3_MULTI_BACKEND_0_ACCESS="primary_key"
export VGW_S3_MULTI_BACKEND_0_SECRET="primary_secret"
export VGW_S3_MULTI_BACKEND_0_ENDPOINT="https://s3.amazonaws.com"
export VGW_S3_MULTI_BACKEND_1_ACCESS="fallback_key"
export VGW_S3_MULTI_BACKEND_1_SECRET="fallback_secret"
export VGW_S3_MULTI_BACKEND_1_ENDPOINT="https://backup-s3.example.com"

# Credenciais do gateway podem ser definidas via env vars ou auto-geradas
export ROOT_ACCESS_KEY="my-gateway-key"  # Opcional
export ROOT_SECRET_KEY="my-gateway-secret"  # Opcional

versitygw s3-multi --config examples/s3-multi-config.json --port :7070
```

### Com Modo Debug

```bash
versitygw s3-multi \
  --config examples/s3-multi-config.json \
  --access ROOT_ACCESS_KEY \
  --secret ROOT_SECRET_KEY \
  --port :7070 \
  --debug
```

## Como Funciona

### Operações de Leitura (GET, HEAD, LIST)
Quando um cliente requisita um objeto:
1. VersityGW primeiro tenta o backend primário
2. Se o objeto não for encontrado (404), automaticamente tenta o próximo backend
3. Isso continua até que o objeto seja encontrado ou todos os backends tenham sido tentados
4. Se nenhum backend tiver o objeto, um 404 é retornado ao cliente

### Operações de Escrita (PUT, DELETE)
Todas as operações de escrita vão para o backend primário (primeiro) apenas:
- Uploads de objetos (PUT)
- Deleções de objetos (DELETE)
- Criação/deleção de buckets
- Modificações de ACL/policy
- Operações de tagging

### URLs Pré-Assinadas

URLs pré-assinadas funcionam perfeitamente com fallback multi-backend. O gateway re-assina requisições para cada backend automaticamente.

**Como a Expiração Funciona:**
- O tempo de expiração é definido pelo **CLIENTE** ao gerar a URL (não pelo gateway)
- O cliente especifica `--expires-in <segundos>` ao criar a URL pré-assinada
- Gateway valida que a expiração está dentro dos limites: 1 segundo a 7 dias (604800 segundos)
- Expiração padrão AWS CLI: 1 hora (3600 segundos) se não especificado

**Definindo o Tempo de Expiração:**

```bash
# Gerar URL com 5 minutos de validade
aws s3 presign s3://mybucket/arquivo.txt \
  --expires-in 300 \
  --endpoint-url http://localhost:7070

# Gerar URL com 24 horas de validade
aws s3 presign s3://mybucket/arquivo.txt \
  --expires-in 86400 \
  --endpoint-url http://localhost:7070

# Gerar URL com expiração máxima (7 dias)
aws s3 presign s3://mybucket/arquivo.txt \
  --expires-in 604800 \
  --endpoint-url http://localhost:7070
```

**Tempos de Expiração Comuns:**
- 5 minutos: `--expires-in 300`
- 30 minutos: `--expires-in 1800`
- 1 hora: `--expires-in 3600` (padrão)
- 24 horas: `--expires-in 86400`
- 7 dias: `--expires-in 604800` (máximo)

**Comportamento Multi-Backend:**
- URLs pré-assinadas tentam cada backend até encontrar o objeto
- Expiração é validada para cada tentativa de backend
- Uma vez expirada, a URL é rejeitada em TODOS os backends

## Opções de Configuração

### Credenciais do Gateway (Geração Aleatória)

O VersityGW pode gerar automaticamente credenciais aleatórias para o gateway:

- Se você **não fornecer** `--access` e `--secret` (ou env vars `ROOT_ACCESS_KEY` e `ROOT_SECRET_KEY`), o VersityGW gerará credenciais criptograficamente seguras na inicialização
- As credenciais geradas serão exibidas na saída do console
- Essas são as credenciais que os clientes S3 usam para conectar ao gateway (separadas das credenciais dos backends)

Exemplo de saída:
```
⚠️  Generated random ACCESS KEY: k8jN2mP9xQwE4rTyU5iO
⚠️  Generated random SECRET KEY: vL7sD3fG6hJ9kM2nB5vC8xZ1aS4dF7gH9jK2lM5n
```

### Campos de Configuração do Backend

Cada backend no array `backends` suporta estes campos:

- **name** (string): Nome legível para logging/debugging
- **access** (string, obrigatório): AWS access key ID para este backend
- **secret** (string, obrigatório): AWS secret access key para este backend
- **endpoint** (string): URL do endpoint S3 (padrão AWS se vazio)
- **region** (string): Região AWS (padrão "us-east-1")
- **metaBucket** (string): Meta bucket para armazenar ACLs/policies
- **disableChecksum** (bool): Desabilitar validação de checksum
- **sslSkipVerify** (bool): Pular verificação de certificado SSL
- **usePathStyle** (bool): Usar endereçamento path-style ao invés de virtual-host style

## Cenários de Exemplo

### Cenário 1: Cloudflare R2 Dual Bucket (Recomendado)

Perfeito para configuração multi-backend econômica com Cloudflare R2:

```json
{
  "backends": [
    {
      "name": "r2-primary-bucket",
      "access": "SUA_CHAVE_ACESSO_R2",
      "secret": "SUA_CHAVE_SECRETA_R2",
      "endpoint": "https://SEU_ID_CONTA.r2.cloudflarestorage.com/primary-bucket",
      "region": "us-east-1"
    },
    {
      "name": "r2-fallback-bucket",
      "access": "SUA_CHAVE_ACESSO_R2",
      "secret": "SUA_CHAVE_SECRETA_R2",
      "endpoint": "https://SEU_ID_CONTA.r2.cloudflarestorage.com/fallback-bucket",
      "region": "us-east-1"
    }
  ]
}
```

**Importante:** Para Cloudflare R2, use `"region": "us-east-1"` na configuração do backend. O AWS CLI também deve usar `us-east-1` como região (`export AWS_DEFAULT_REGION=us-east-1` ou `aws configure set region us-east-1`).

**Execute com credenciais aleatórias do gateway:**
```bash
versitygw s3-multi --config r2-config.json --port :7070
# Gateway gerará automaticamente e exibirá chaves ACCESS/SECRET
```

Veja `examples/s3-multi-cloudflare-r2.json` para um template completo.

### Cenário 2: AWS S3 com Backup On-Premises
```json
{
  "backends": [
    {
      "name": "aws-s3-primary",
      "access": "AWS_KEY",
      "secret": "AWS_SECRET",
      "endpoint": "",
      "region": "us-east-1"
    },
    {
      "name": "local-minio",
      "access": "MINIO_KEY",
      "secret": "MINIO_SECRET",
      "endpoint": "https://minio.local:9000",
      "region": "us-east-1",
      "usePathStyle": true
    }
  ]
}
```

### Cenário 3: Fallback Multi-Região
```json
{
  "backends": [
    {
      "name": "us-east",
      "access": "KEY1",
      "secret": "SECRET1",
      "endpoint": "https://s3.us-east-1.amazonaws.com",
      "region": "us-east-1"
    },
    {
      "name": "eu-west",
      "access": "KEY2",
      "secret": "SECRET2",
      "endpoint": "https://s3.eu-west-1.amazonaws.com",
      "region": "eu-west-1"
    }
  ]
}
```

### Cenário 4: Fallback de Três Camadas
```json
{
  "backends": [
    {
      "name": "hot-storage",
      "access": "HOT_KEY",
      "secret": "HOT_SECRET",
      "endpoint": "https://fast-s3.example.com",
      "region": "us-east-1"
    },
    {
      "name": "warm-storage",
      "access": "WARM_KEY",
      "secret": "WARM_SECRET",
      "endpoint": "https://s3.example.com",
      "region": "us-east-1"
    },
    {
      "name": "cold-storage",
      "access": "COLD_KEY",
      "secret": "COLD_SECRET",
      "endpoint": "https://glacier-s3.example.com",
      "region": "us-east-1"
    }
  ]
}
```

## Testes

### Testar Comportamento de Fallback

1. Inicie o VersityGW com configuração multi-backend
2. Faça upload de um arquivo (vai para o backend primário apenas):
   ```bash
   aws s3 cp test.txt s3://mybucket/test.txt --endpoint-url http://localhost:7070
   ```

3. O arquivo agora está apenas no backend primário

4. Tente ler o arquivo (deve ter sucesso do primário):
   ```bash
   aws s3 cp s3://mybucket/test.txt downloaded.txt --endpoint-url http://localhost:7070
   ```

5. Para testar o fallback, manualmente faça upload de um arquivo para o backend secundário fora do VersityGW, então tente lê-lo através do VersityGW - ele deve encontrá-lo no backend de fallback

## Limitações

- Uploads multipart são suportados apenas no backend primário
- Consultas de versionamento de objetos consultam apenas o backend primário
- Listagem de buckets combina resultados de todos os backends (pode mostrar nomes de bucket duplicados)
- Sem sincronização automática entre backends
- Operações de escrita não replicam para backends de fallback
