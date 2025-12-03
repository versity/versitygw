# Presigned URLs - Configuração de Expiração

## Como Funciona

### ⏰ Tempo de Expiração

O tempo de expiração das **presigned URLs** é definido pelo **CLIENTE** no momento da geração da URL, **NÃO** pelo gateway.

### Quem Define

- ✅ **AWS CLI**: Define via flag `--expires-in`
- ✅ **AWS SDK**: Define via parâmetro `expires`
- ✅ **Código customizado**: Define ao chamar a função de presign

### Limites do Servidor

O gateway VersityGW valida os limites do S3:

| Limite | Valor | Descrição |
|--------|-------|-----------|
| **Mínimo** | 1 segundo | Não pode ser negativo ou zero |
| **Máximo** | 604800 segundos | 7 dias (1 semana) |
| **Padrão AWS CLI** | 3600 segundos | 1 hora (se não especificar) |

## 🔍 Validação no Gateway

O código valida:

```go
// s3err/presigned-urls.go
ExpiresTooLarge: "X-Amz-Expires must be less than a week (604800 seconds)"
ExpiresNegative: "X-Amz-Expires must be non-negative"
ExpiresNumber: "X-Amz-Expires should be a number"
```

## 📝 Como Configurar

### 1. AWS CLI

```bash
# Expiração padrão (1 hora = 3600 segundos)
aws s3 presign s3://bucket/file.txt

# Expiração customizada (10 minutos = 600 segundos)
aws s3 presign s3://bucket/file.txt --expires-in 600

# Expiração de 24 horas (86400 segundos)
aws s3 presign s3://bucket/file.txt --expires-in 86400

# Expiração máxima (7 dias = 604800 segundos)
aws s3 presign s3://bucket/file.txt --expires-in 604800
```

### 2. AWS SDK Go

```go
import (
    "github.com/aws/aws-sdk-go/service/s3"
    "time"
)

// Criar presigned URL com 2 horas de validade
req, _ := s3Client.GetObjectRequest(&s3.GetObjectInput{
    Bucket: aws.String("my-bucket"),
    Key:    aws.String("my-file.txt"),
})

url, err := req.Presign(2 * time.Hour)
```

### 3. AWS SDK Python (boto3)

```python
import boto3
from botocore.client import Config

s3_client = boto3.client('s3', config=Config(signature_version='s3v4'))

# Gerar URL válida por 30 minutos (1800 segundos)
url = s3_client.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'my-bucket', 'Key': 'my-file.txt'},
    ExpiresIn=1800
)
```

### 4. AWS SDK JavaScript

```javascript
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

// Gerar URL válida por 5 minutos (300 segundos)
const url = s3.getSignedUrl('getObject', {
    Bucket: 'my-bucket',
    Key: 'my-file.txt',
    Expires: 300
});
```

## 🎯 Exemplos Práticos

### Caso 1: Download Temporário (5 minutos)

```bash
# Cliente gera URL que expira em 5 minutos
aws s3 presign s3://mybucket/temp-file.pdf \
  --expires-in 300 \
  --endpoint-url http://localhost:7070

# URL gerada (exemplo):
# http://localhost:7070/mybucket/temp-file.pdf?
#   X-Amz-Algorithm=AWS4-HMAC-SHA256&
#   X-Amz-Credential=...&
#   X-Amz-Date=20231203T120000Z&
#   X-Amz-Expires=300&           <-- 5 minutos
#   X-Amz-SignedHeaders=host&
#   X-Amz-Signature=...
```

### Caso 2: Compartilhamento de Longo Prazo (24 horas)

```bash
# URL válida por 24 horas
aws s3 presign s3://mybucket/shared-document.docx \
  --expires-in 86400 \
  --endpoint-url http://localhost:7070
```

### Caso 3: Link Máximo (7 dias)

```bash
# URL válida pelo máximo permitido
aws s3 presign s3://mybucket/archive.zip \
  --expires-in 604800 \
  --endpoint-url http://localhost:7070
```

## ⚙️ Configuração Docker

### Via Environment Variables

No Docker setup, não há variável específica para expiração porque:
- ✅ O tempo é definido pelo **cliente**
- ✅ O gateway apenas **valida** os limites
- ✅ Nenhuma configuração adicional necessária

### Exemplo Docker + AWS CLI

```bash
# Start gateway
cd docker
docker-compose up -d

# Configure client
export AWS_ACCESS_KEY_ID=<gateway-key>
export AWS_SECRET_ACCESS_KEY=<gateway-secret>
export AWS_ENDPOINT_URL=http://localhost:7070
export AWS_DEFAULT_REGION=us-east-1

# Gerar presigned URL com tempo customizado
aws s3 presign s3://mybucket/file.txt --expires-in 1800
```

## 🔒 Segurança

### Boas Práticas

1. **Minimize o tempo** - Use o menor tempo necessário
2. **Arquivos sensíveis** - Use 5-15 minutos
3. **Compartilhamento** - Use 1-24 horas
4. **Arquivos públicos** - Use até 7 dias (mas considere outros métodos)

### Recomendações por Caso de Uso

| Caso de Uso | Tempo Recomendado |
|-------------|-------------------|
| Upload temporário | 5-15 minutos |
| Download de relatório | 30 minutos - 2 horas |
| Compartilhamento de documento | 4-24 horas |
| Link de backup | 7 dias (máximo) |
| API temporária | 15-60 minutos |

## 🧪 Testando Expiração

### Teste 1: URL Expirada

```bash
# Gerar URL com 10 segundos
aws s3 presign s3://bucket/file.txt --expires-in 10

# Aguardar 15 segundos
sleep 15

# Tentar acessar (deve falhar)
curl "<url-gerada>"
# Resultado: Request has expired (403)
```

### Teste 2: URL Válida

```bash
# Gerar URL com 5 minutos
aws s3 presign s3://bucket/file.txt --expires-in 300

# Acessar imediatamente (deve funcionar)
curl "<url-gerada>" -o downloaded-file.txt
```

### Teste 3: Limite Excedido

```bash
# Tentar gerar URL com mais de 7 dias (deve falhar)
aws s3 presign s3://bucket/file.txt --expires-in 700000
# Erro: X-Amz-Expires must be less than 604800 seconds
```

## 📊 Formato da URL

A expiração é incluída no query parameter `X-Amz-Expires`:

```
http://gateway:7070/bucket/object?
  X-Amz-Algorithm=AWS4-HMAC-SHA256&
  X-Amz-Credential=ACCESS_KEY/20231203/us-east-1/s3/aws4_request&
  X-Amz-Date=20231203T120000Z&
  X-Amz-Expires=3600&                    <-- TEMPO EM SEGUNDOS
  X-Amz-SignedHeaders=host&
  X-Amz-Signature=abc123...
```

## 🔄 Multi-Backend e Expiração

No modo multi-backend:
- ✅ Presigned URLs funcionam com **todos os backends**
- ✅ O gateway re-assina a requisição para cada backend
- ✅ O tempo de expiração é **respeitado** em todos os backends
- ✅ Fallback funciona normalmente dentro do tempo válido

```bash
# Cliente gera URL (1 hora)
aws s3 presign s3://bucket/file.txt --expires-in 3600

# Gateway tenta:
# 1. Backend primário (dentro de 1h)
# 2. Backend fallback (dentro de 1h) 
# 3. Após 1h = expirado em TODOS os backends
```

## 🎓 Resumo

| Aspecto | Detalhes |
|---------|----------|
| **Quem define** | Cliente (AWS CLI, SDK, código) |
| **Onde configurar** | Na chamada de geração da URL |
| **Gateway valida** | Sim (limites: 1s - 604800s) |
| **Padrão AWS** | 3600 segundos (1 hora) |
| **Máximo S3** | 604800 segundos (7 dias) |
| **Configuração no gateway** | Não necessária |
| **Multi-backend** | Funciona em todos os backends |

---

**Importante**: O gateway VersityGW **não controla** o tempo de expiração. Ele apenas:
1. ✅ Valida que está dentro dos limites (1s - 7 dias)
2. ✅ Verifica se a URL ainda não expirou
3. ✅ Retorna erro 403 se expirada

Para controlar o tempo, configure no **cliente** ao gerar a URL!
