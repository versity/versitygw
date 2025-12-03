# VersityGW Multi-Backend Fork

> **Fork do [versity/versitygw](https://github.com/versity/versitygw)** com suporte multi-backend S3 e fallback automático.

**[English Documentation](README.md)** | **Documentação em Português**

## Novidades Neste Fork

### Gateway S3 Multi-Backend com Fallback Automático

Este fork adiciona arquitetura multi-backend transparente que permite:

- **Fallback Automático Entre Backends**: Operações de leitura (GET/HEAD/LIST) tentam todos os backends configurados sequencialmente até encontrar o objeto
- **Múltiplos Backends S3-Compatíveis**: Funciona com Cloudflare R2, MinIO, AWS S3, Azure e qualquer storage compatível com S3
- **Operações de Escrita Inteligentes**: PUT/DELETE sempre vão para o backend primário apenas
- **URLs Pré-Assinadas**: Assinatura AWS SigV4 completa com expiração configurável (aproveita feature existente do Versity)
- **Detecção Robusta de Erros**: Distingue NoSuchKey (404) de outros erros para garantir comportamento de fallback adequado
- **🔐 Credenciais Aleatórias**: Auto-gera credenciais seguras do gateway se não forem fornecidas (baseado em crypto/rand)

### Novos Arquivos Adicionados

- `backend/multibackend.go` (623 linhas) - Wrapper multi-backend com lógica de fallback
- `cmd/versitygw/s3multi.go` (261 linhas) - Novo comando CLI para modo multi-backend
- `examples/README-s3-multi.md` - Documentação completa de uso
- `examples/s3-multi-config.json` - Template de configuração
- `examples/s3-multi-cloudflare-r2.json` - Template específico para Cloudflare R2
- `multibackend-implementation.patch` - Arquivo patch para aplicação fácil no upstream

### Início Rápido com Multi-Backend

```bash
# Crie o arquivo de configuração
cat > config.json << 'EOF'
{
  "backends": [
    {
      "name": "primary-r2",
      "access": "SUA_CHAVE_ACESSO_R2",
      "secret": "SUA_CHAVE_SECRETA_R2",
      "endpoint": "https://conta.r2.cloudflarestorage.com/bucket-primario",
      "region": "auto"
    },
    {
      "name": "fallback-r2",
      "access": "SUA_CHAVE_ACESSO_R2",
      "secret": "SUA_CHAVE_SECRETA_R2",
      "endpoint": "https://conta.r2.cloudflarestorage.com/bucket-fallback",
      "region": "auto"
    }
  ]
}
EOF

# Compile
make build

# Execute com credenciais aleatórias automáticas (mais fácil!)
./bin/versitygw --port :7070 s3-multi --config config.json
# ⚠️  Generated random ACCESS KEY: kNnIst0KOxuyBbozuF-l
# ⚠️  Generated random SECRET KEY: mZA4WE4HFydNcBubWCozuXkG8-Z03afd5KWlFAp1

# Ou forneça suas próprias credenciais do gateway
./bin/versitygw --port :7070 --access admin --secret senha s3-multi --config config.json
```

**Nota Importante:** As credenciais dos backends (no JSON) são para conectar ao R2/S3. As credenciais do gateway (--access/--secret) são o que os clientes S3 usam para conectar ao VersityGW. Se omitidas, são geradas automaticamente.

### 🔐 Credenciais Automáticas (Nova Feature!)

O VersityGW agora pode gerar credenciais criptograficamente seguras automaticamente:

**Como funciona:**
- Se você **NÃO** fornecer `--access` e `--secret` (ou variáveis de ambiente `ROOT_ACCESS_KEY` e `ROOT_SECRET_KEY`)
- O VersityGW gerará credenciais aleatórias usando `crypto/rand`
- As credenciais serão exibidas no console na inicialização
- Você usa essas credenciais para configurar seus clientes S3 (aws-cli, boto3, etc.)

**Exemplo:**
```bash
./bin/versitygw --port :7070 s3-multi --config config.json
```

**Saída:**
```
⚠️  Generated random ACCESS KEY: kNnIst0KOxuyBbozuF-l
⚠️  Generated random SECRET KEY: mZA4WE4HFydNcBubWCozuXkG8-Z03afd5KWlFAp1
Multi-backend initialized with 2 S3 backends
Primary backend: primary-r2
Fallback backends: fallback-r2
```

**Configure seu cliente S3:**
```bash
aws configure
# AWS Access Key ID: kNnIst0KOxuyBbozuF-l
# AWS Secret Access Key: mZA4WE4HFydNcBubWCozuXkG8-Z03afd5KWlFAp1
# Default region: us-east-1

aws s3 ls --endpoint-url http://localhost:7070
```

**Benefícios:**
- ✅ **Segurança**: Usa `crypto/rand` (criptograficamente seguro)
- ✅ **Conveniência**: Não precisa configurar credenciais para testes
- ✅ **Flexibilidade**: Ainda aceita credenciais customizadas via CLI/env
- ✅ **Zero configuração**: Funciona out-of-the-box
- ✅ **Único por instância**: Cada execução gera credenciais diferentes

### Casos de Uso para Multi-Backend

- **Alta Disponibilidade**: Failover automático para storage de backup se o primário estiver indisponível
- **Migração de Dados**: Acesse dados de múltiplas fontes durante períodos de migração
- **Acesso Multi-Região**: Leia do backend mais próximo/rápido disponível
- **Otimização de Custos**: Armazene dados quentes em storage premium, arquive em backends mais baratos

### Status de Testes

Totalmente testado com configuração dual-bucket do Cloudflare R2:
- ✅ Listar buckets através de múltiplos backends
- ✅ Upload/Download com verificação de integridade
- ✅ Geração e validação de URL pré-assinada
- ✅ Fallback automático para backend secundário
- ✅ Tratamento de erro 404
- ✅ Geração de credenciais aleatórias

Veja [`examples/README-s3-multi.md`](examples/README-s3-multi.md) para documentação completa.

---

## Como Funciona o Fallback

### Operações de Leitura (GET, HEAD, LIST)
```
Cliente → VersityGW → Backend 1 (primário)
                     ↓ (se 404)
                     Backend 2 (fallback)
                     ↓ (se 404)
                     Retorna 404
```

### Operações de Escrita (PUT, DELETE)
```
Cliente → VersityGW → Backend 1 (primário apenas)
```

---

## Instalação e Uso

### Pré-requisitos
- Go 1.24.0 ou superior
- Acesso a backends S3-compatíveis (Cloudflare R2, MinIO, AWS S3, etc.)

### Compilação

```bash
git clone https://github.com/klaoslacerdacs/versitygw-multibackend.git
cd versitygw-multibackend
make build
```

### Configuração

Crie um arquivo JSON com seus backends:

```json
{
  "backends": [
    {
      "name": "primary-r2",
      "access": "9b5e212b5da57b6fd67f938b2de9c1d5",
      "secret": "d06434439ad24ead24d80688494462b0b4cd89b45c07306d71a7a533f8b6d26d",
      "endpoint": "https://9cf30e99d849125d9bc261b19b175489.r2.cloudflarestorage.com/anexos",
      "region": "auto"
    },
    {
      "name": "fallback-r2",
      "access": "9b5e212b5da57b6fd67f938b2de9c1d5",
      "secret": "d06434439ad24ead24d80688494462b0b4cd89b45c07306d71a7a533f8b6d26d",
      "endpoint": "https://9cf30e99d849125d9bc261b19b175489.r2.cloudflarestorage.com/apostas",
      "region": "auto"
    }
  ]
}
```

### Execução

```bash
# Com credenciais aleatórias (recomendado para testes)
./bin/versitygw --port :7070 s3-multi --config config.json

# Com credenciais fixas (produção)
./bin/versitygw --port :7070 --access admin --secret senha123 s3-multi --config config.json

# Com variáveis de ambiente
export ROOT_ACCESS_KEY="minha-chave"
export ROOT_SECRET_KEY="minha-senha"
./bin/versitygw --port :7070 s3-multi --config config.json
```

---

## Exemplos de Configuração

### Cloudflare R2 Dual-Bucket (Recomendado)

Veja o template completo em [`examples/s3-multi-cloudflare-r2.json`](examples/s3-multi-cloudflare-r2.json)

### AWS S3 com Backup On-Premises

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

### Multi-Região com 3 Tiers

```json
{
  "backends": [
    {
      "name": "hot-storage",
      "access": "KEY1",
      "secret": "SECRET1",
      "endpoint": "https://fast-s3.example.com",
      "region": "us-east-1"
    },
    {
      "name": "warm-storage",
      "access": "KEY2",
      "secret": "SECRET2",
      "endpoint": "https://s3.example.com",
      "region": "us-east-1"
    },
    {
      "name": "cold-storage",
      "access": "KEY3",
      "secret": "SECRET3",
      "endpoint": "https://glacier-s3.example.com",
      "region": "us-east-1"
    }
  ]
}
```

---

## Aplicar Patch no Versity Original

Se você quiser aplicar apenas as mudanças no Versity original:

```bash
# Clone o Versity original
git clone https://github.com/versity/versitygw.git
cd versitygw

# Baixe e aplique o patch
wget https://raw.githubusercontent.com/klaoslacerdacs/versitygw-multibackend/main/multibackend-implementation.patch
git apply multibackend-implementation.patch

# Compile
make build
```

---

## Limitações

- Uploads multipart são suportados apenas no backend primário
- Consultas de versionamento de objetos consultam apenas o backend primário
- Listagem de buckets combina resultados de todos os backends (pode mostrar nomes de bucket duplicados)
- Sem sincronização automática entre backends
- Operações de escrita não replicam para backends de fallback

---

## Contribuindo

Este é um fork independente. Para contribuir:

1. Faça fork deste repositório
2. Crie uma branch para sua feature
3. Faça commit das mudanças
4. Envie um pull request

---

## Licença

Apache License 2.0 - mesmo que o [Versity Gateway original](https://github.com/versity/versitygw)

---

## Links Úteis

- **Repositório Original**: https://github.com/versity/versitygw
- **Este Fork**: https://github.com/klaoslacerdacs/versitygw-multibackend
- **Patch File**: [multibackend-implementation.patch](multibackend-implementation.patch)
- **Documentação Completa**: [examples/README-s3-multi.md](examples/README-s3-multi.md)
- **Template Cloudflare R2**: [examples/s3-multi-cloudflare-r2.json](examples/s3-multi-cloudflare-r2.json)

---

## Suporte

Para questões sobre este fork:
- Abra uma issue no GitHub
- Veja a documentação do [Versity original](https://github.com/versity/versitygw/wiki)

---

# O Versity S3 Gateway Original

Documentação do gateway original continua abaixo...

---

# The Versity S3 Gateway:<br/>A High-Performance S3 Translation Service

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/versity/versitygw/blob/assets/assets/logo-white.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/versity/versitygw/blob/assets/assets/logo.svg">
  <a href="https://www.versity.com"><img alt="Imagem do logo da Versity Software." src="https://github.com/versity/versitygw/blob/assets/assets/logo.svg"></a>
</picture>

 [![Apache V2 License](https://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/versity/versitygw/blob/main/LICENSE) [![Go Report Card](https://goreportcard.com/badge/github.com/versity/versitygw)](https://goreportcard.com/report/github.com/versity/versitygw) [![Go Reference](https://pkg.go.dev/badge/github.com/versity/versitygw.svg)](https://pkg.go.dev/github.com/versity/versitygw)

### Builds binários de release
Baixe a [última release](https://github.com/versity/versitygw/releases)
 | Linux/amd64 | Linux/arm64 | MacOS/amd64 | MacOS/arm64 | BSD/amd64 | BSD/arm64 |
 |:-----------:|:-----------:|:-----------:|:-----------:|:---------:|:---------:|
 |    ✔️    |  ✔️  |   ✔️   |  ✔️   |  ✔️   |  ✔️   |
 
### Casos de Uso
* Transforme seu sistema de arquivos local em um servidor S3 com um único comando!
* Proxy de requisições S3 para storage S3
* Servidor S3 simples de implantar com um único comando
* Compatibilidade de protocolo em `posix` permite acesso comum a arquivos via posix ou S3
* Interface simplificada para adicionar suporte a novos sistemas de storage

### Notícias
Confira os últimos artigos da wiki: [https://github.com/versity/versitygw/wiki/Articles](https://github.com/versity/versitygw/wiki/Articles)

### Lista de E-mail
Mantenha-se atualizado com os últimos anúncios do gateway inscrevendo-se na [lista de e-mails versitygw](https://www.versity.com/products/versitygw#signup).

### Documentação
Veja a [documentação](https://github.com/versity/versitygw/wiki) do projeto na wiki.

### Precisa de ajuda?
Faça perguntas nas [discussões da comunidade](https://github.com/versity/versitygw/discussions).
<br>
Contate [Versity Sales](https://www.versity.com/contact/) para discutir suporte empresarial.

### Visão Geral
Versity Gateway, uma ferramenta simples de usar para tradução inline transparente entre comandos de objetos AWS S3 e sistemas de storage. O Versity Gateway conecta aplicações dependentes de S3 a outros sistemas de storage, habilitando compatibilidade e integração aprimoradas enquanto oferece escalabilidade excepcional.

O servidor traduz requisições de API S3 recebidas e as transforma em operações equivalentes para o serviço backend. Ao aproveitar este servidor gateway, aplicações podem interagir com a API compatível com S3 em cima de sistemas de storage já existentes. Este projeto permite aproveitar investimentos de infraestrutura existentes enquanto integra perfeitamente com sistemas compatíveis com S3, oferecendo maior flexibilidade e compatibilidade no gerenciamento de armazenamento de dados.

O Versity Gateway é focado em performance, simplicidade e expansibilidade. O Versity Gateway é projetado com modularidade em mente, habilitando futuras extensões para suportar sistemas de storage backend adicionais. Atualmente, o Versity Gateway suporta qualquer backend de arquivo POSIX genérico, o sistema de arquivos ScoutFS open source da Versity, Azure Blob Storage, e outros servidores S3.

O gateway é completamente stateless. Múltiplas instâncias do Versity Gateway podem ser implantadas em um cluster para aumentar o throughput agregado. A arquitetura stateless do Versity Gateway permite que qualquer requisição seja atendida por qualquer gateway, distribuindo assim cargas de trabalho e melhorando a performance. Balanceadores de carga podem ser usados para distribuir uniformemente requisições através do cluster de gateways para performance ótima.

O servidor HTTP(S) S3 e roteamento é implementado usando o framework web [Fiber](https://gofiber.io). Este framework é ativamente desenvolvido com foco em performance. A compatibilidade da API S3 aproveita o [aws-sdk-go-v2](https://github.com/aws/aws-sdk-go-v2) oficial sempre que possível para máxima compatibilidade de serviço com AWS S3.

### Contato

![versity logo](https://www.versity.com/wp-content/uploads/2022/12/cropped-android-chrome-512x512-1-32x32.png)
info@versity.com <br />
+1 844 726 8826

### @versitysoftware 
[![linkedin](https://github.com/versity/versitygw/blob/assets/assets/linkedin.jpg)](https://www.linkedin.com/company/versity/) &nbsp; 
[![twitter](https://github.com/versity/versitygw/blob/assets/assets/twitter.jpg)](https://twitter.com/VersitySoftware) &nbsp;
[![facebook](https://github.com/versity/versitygw/blob/assets/assets/facebook.jpg)](https://www.facebook.com/versitysoftware) &nbsp;
[![instagram](https://github.com/versity/versitygw/blob/assets/assets/instagram.jpg)](https://www.instagram.com/versitysoftware/) &nbsp;
