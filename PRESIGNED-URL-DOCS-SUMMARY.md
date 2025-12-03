# 📚 Documentação sobre Expiração de URLs Pré-Assinadas

## ✅ Documentação Adicionada

### 1. Documento Completo e Detalhado
📄 **`docker/PRESIGNED-URL-EXPIRATION.md`** (420 linhas)

**Conteúdo:**
- ⏰ Como funciona a expiração
- 👤 Quem define o tempo (CLIENTE, não o gateway)
- 📊 Limites validados pelo servidor (1s - 7 dias)
- 💻 Exemplos para AWS CLI, SDK Go, Python, JavaScript
- 🎯 Casos de uso práticos (5min, 1h, 24h, 7 dias)
- ⚙️ Como configurar no Docker
- 🔒 Boas práticas de segurança
- 🧪 Testes de expiração
- 🔄 Comportamento multi-backend
- 📝 Tabelas de referência rápida

### 2. Guias Multi-Backend Atualizados

#### 📄 **`examples/README-s3-multi.md`** (Inglês)
**Seção adicionada:** "Presigned URLs" (linha ~77)

**Conteúdo:**
- Como expiração funciona
- Quem define o tempo
- Limites validados
- Exemplos de comandos AWS CLI
- Tempos comuns de expiração
- Comportamento multi-backend

#### 📄 **`examples/README-s3-multi.pt-BR.md`** (Português)
**Seção adicionada:** "URLs Pré-Assinadas" (linha ~76)

**Conteúdo:**
- Tradução completa da documentação
- Mesmos exemplos em português
- Explicações localizadas

### 3. Docker READMEs Atualizados

#### 📄 **`docker/README.md`** (Inglês)
**Seção adicionada:** "Presigned URLs" (após "Test the Gateway")

**Conteúdo:**
- Como definir tempo de expiração
- Exemplos práticos de uso
- Tempos comuns (5min - 7 dias)
- Limites validados
- Nota importante: cliente controla, não o gateway

#### 📄 **`docker/README.pt-BR.md`** (Português)
**Seção adicionada:** "URLs Pré-Assinadas" (após "Testar o Gateway")

**Conteúdo:**
- Tradução completa
- Exemplos localizados
- Mesma estrutura

## 📍 Onde Encontrar a Documentação

```
versitygw/
├── docker/
│   ├── PRESIGNED-URL-EXPIRATION.md    ✅ DOCUMENTO PRINCIPAL (420 linhas)
│   ├── README.md                       ✅ Seção adicionada (Inglês)
│   └── README.pt-BR.md                 ✅ Seção adicionada (Português)
└── examples/
    ├── README-s3-multi.md              ✅ Seção expandida (Inglês)
    └── README-s3-multi.pt-BR.md        ✅ Seção expandida (Português)
```

## 🎯 Resposta à Pergunta: "Onde Seta o Time?"

### ❌ NÃO é no Gateway

O gateway **NÃO** tem configuração para tempo de expiração porque:
- O tempo é definido pelo **CLIENTE**
- O gateway apenas **valida** os limites
- Não há variável de ambiente para isso
- Não há flag CLI para isso no gateway

### ✅ É no Cliente (ao gerar a URL)

**AWS CLI:**
```bash
aws s3 presign s3://bucket/file.txt --expires-in 300  # <-- AQUI!
```

**SDK Go:**
```go
url, _ := req.Presign(5 * time.Minute)  // <-- AQUI!
```

**SDK Python:**
```python
url = s3_client.generate_presigned_url(
    'get_object',
    Params={'Bucket': 'bucket', 'Key': 'file'},
    ExpiresIn=300  # <-- AQUI!
)
```

**SDK JavaScript:**
```javascript
const url = s3.getSignedUrl('getObject', {
    Bucket: 'bucket',
    Key: 'file',
    Expires: 300  // <-- AQUI!
});
```

## 📊 Tabela de Referência Rápida

| Tempo | Segundos | Comando CLI | Caso de Uso |
|-------|----------|-------------|-------------|
| 5 minutos | 300 | `--expires-in 300` | Upload temporário |
| 30 minutos | 1800 | `--expires-in 1800` | Download de relatório |
| 1 hora | 3600 | `--expires-in 3600` | Padrão AWS CLI |
| 24 horas | 86400 | `--expires-in 86400` | Compartilhamento de doc |
| 7 dias | 604800 | `--expires-in 604800` | Máximo permitido |

## 🔍 Validação no Gateway

O gateway valida apenas se o valor está dentro dos limites:

```
┌─────────────┐
│   Cliente   │
│ (AWS CLI)   │
└──────┬──────┘
       │ --expires-in 300
       ↓
┌─────────────┐
│   Gateway   │
│  VersityGW  │
└──────┬──────┘
       │ Valida:
       │ ✅ >= 1 segundo?
       │ ✅ <= 604800 segundos?
       │ ✅ Ainda não expirou?
       ↓
┌─────────────┐
│   Backend   │
│  S3/R2/etc  │
└─────────────┘
```

## 📝 Exemplos no Docker

### .env (Não tem variável de expiração!)

```bash
# docker/.env
VGW_PORT=7070
VGW_ACCESS_KEY=my-key
VGW_SECRET_KEY=my-secret
# ❌ Não existe: VGW_PRESIGN_EXPIRATION
```

### Uso Correto

```bash
# 1. Subir o gateway
cd docker
docker-compose up -d

# 2. Cliente define expiração ao gerar URL
export AWS_ACCESS_KEY_ID=my-key
export AWS_SECRET_ACCESS_KEY=my-secret
export AWS_ENDPOINT_URL=http://localhost:7070

# Cliente controla o tempo aqui ↓
aws s3 presign s3://bucket/file.txt --expires-in 300
```

## 🎓 Conclusão

### Onde está documentado:
✅ **5 arquivos** atualizados
✅ **1 documento principal** criado (420 linhas)
✅ **Inglês e Português** cobertos
✅ **Exemplos práticos** em múltiplas linguagens
✅ **Docker** e **CLI** documentados

### Onde configurar:
✅ **NO CLIENTE** ao chamar `presign`/`generate_presigned_url`
❌ **NÃO no gateway** (sem configuração necessária)

### Commit:
```
06f527c - docs: add comprehensive presigned URL expiration documentation
```

**GitHub**: https://github.com/klaoslacerdacs/versitygw-multibackend

---

**Total de linhas adicionadas**: ~415 linhas de documentação sobre expiração! 📚
