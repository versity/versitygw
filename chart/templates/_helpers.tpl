{{/*
Expand the name of the chart.
*/}}
{{- define "versitygw.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "versitygw.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "versitygw.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "versitygw.labels" -}}
helm.sh/chart: {{ include "versitygw.chart" . }}
{{ include "versitygw.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
These are the stable labels used in Service selectors and Deployment matchLabels.
They intentionally exclude helm.sh/chart (which includes the version) to prevent
broken selectors during helm upgrades.
*/}}
{{- define "versitygw.selectorLabels" -}}
app.kubernetes.io/name: {{ include "versitygw.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "versitygw.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "versitygw.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The name of the Secret holding the root S3 credentials.
Uses auth.existingSecret if set, otherwise derives a name from the release fullname.
*/}}
{{- define "versitygw.credentialsSecretName" -}}
{{- if .Values.auth.existingSecret }}
{{- printf "%s" .Values.auth.existingSecret }}
{{- else }}
{{- printf "%s-credentials" (include "versitygw.fullname" .) }}
{{- end }}
{{- end }}

{{/*
The root credential Secret used by the standalone IAM API server. It defaults
to the gateway root Secret for backward compatibility, but can be separated so
the public IAM control plane and S3 gateway do not share administrative keys.
*/}}
{{- define "versitygw.iamServerCredentialsSecretName" -}}
{{- $auth := .Values.iamServer.auth | default dict -}}
{{- if $auth.existingSecret }}
{{- $auth.existingSecret }}
{{- else }}
{{- include "versitygw.credentialsSecretName" . }}
{{- end }}
{{- end }}

{{/*
The name of the PVC to use for persistence.
Returns empty string if persistence is disabled.
*/}}
{{- define "versitygw.pvcName" -}}
{{- if .Values.persistence.enabled }}
{{- if .Values.persistence.claimName }}
{{- .Values.persistence.claimName }}
{{- else }}
{{- printf "%s-data" (include "versitygw.fullname" .) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
The name of the TLS Secret used for HTTPS.
Uses certificate.secretName if set, otherwise derives a name from the release fullname.
*/}}
{{- define "versitygw.certificateSecretName" -}}
{{- if .Values.certificate.secretName }}
{{- printf "%s" .Values.certificate.secretName }}
{{- else }}
{{- printf "%s-cert" (include "versitygw.fullname" .) }}
{{- end }}
{{- end }}

{{/*
The name label for the standalone IAM API server. It must differ from the
gateway's name label because the gateway Deployment's immutable selector only
contains app.kubernetes.io/name and app.kubernetes.io/instance. Reusing that
pair would make the gateway Deployment, Service, and NetworkPolicy also select
IAM server pods.
*/}}
{{- define "versitygw.iamServerName" -}}
{{- $base := include "versitygw.name" . | trunc 59 | trimSuffix "-" -}}
{{- printf "%s-iam" $base }}
{{- end }}

{{/*
The fullname of the standalone IAM API server's Deployment/Service.
*/}}
{{- define "versitygw.iamServerFullname" -}}
{{- $base := include "versitygw.fullname" . | trunc 59 | trimSuffix "-" -}}
{{- printf "%s-iam" $base }}
{{- end }}

{{/*
The standalone IAM private Service is always cluster-internal, independently
of how the public control-plane Service is exposed.
*/}}
{{- define "versitygw.iamServerPrivateServiceFullname" -}}
{{- $base := include "versitygw.fullname" . | trunc 51 | trimSuffix "-" -}}
{{- printf "%s-iam-private" $base }}
{{- end }}

{{/*
Selector labels for the standalone IAM API server. Deliberately separate from
versitygw.selectorLabels (used by the main gateway Deployment's immutable
spec.selector) so the two Deployments never collide.
*/}}
{{- define "versitygw.iamServerSelectorLabels" -}}
app.kubernetes.io/name: {{ include "versitygw.iamServerName" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: iam-server
{{- end }}

{{/*
Common labels for the standalone IAM API server.
*/}}
{{- define "versitygw.iamServerLabels" -}}
helm.sh/chart: {{ include "versitygw.chart" . }}
{{ include "versitygw.iamServerSelectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
The name of the PVC used for the standalone IAM API server's file-backed storage.
Returns empty string if persistence is disabled.
*/}}
{{- define "versitygw.iamServerPvcName" -}}
{{- if .Values.iamServer.persistence.enabled }}
{{- if .Values.iamServer.persistence.claimName }}
{{- .Values.iamServer.persistence.claimName }}
{{- else }}
{{- $base := include "versitygw.fullname" . | trunc 54 | trimSuffix "-" -}}
{{- printf "%s-iam-data" $base }}
{{- end }}
{{- end }}
{{- end }}

{{/*
The name of the Secret holding the standalone IAM API server's private-listener
server certificate (tls.crt/tls.key) and the CA (ca.crt) used to verify gateway
client certificates. Uses iamServer.private.certificate.existingSecret if set,
otherwise derives a name for the cert-manager-managed Certificate.
*/}}
{{- define "versitygw.iamServerPrivateCertSecretName" -}}
{{- if .Values.iamServer.private.certificate.existingSecret }}
{{- .Values.iamServer.private.certificate.existingSecret }}
{{- else }}
{{- printf "%s-private-cert" (include "versitygw.iamServerFullname" .) }}
{{- end }}
{{- end }}

{{/*
The name of the Secret holding the gateway's mTLS client certificate
(tls.crt/tls.key) and the CA (ca.crt) used to verify the standalone IAM
service's server certificate. Uses iam.standalone.certificate.existingSecret
if set, otherwise derives a name for the cert-manager-managed Certificate.
*/}}
{{- define "versitygw.iamClientCertSecretName" -}}
{{- if .Values.iam.standalone.certificate.existingSecret }}
{{- .Values.iam.standalone.certificate.existingSecret }}
{{- else }}
{{- printf "%s-iam-client-cert" (include "versitygw.fullname" .) }}
{{- end }}
{{- end }}

{{/*
The gateway's standalone-IAM private endpoint address. Uses
iam.standalone.endpoint if set, otherwise auto-targets the in-chart iamServer
Service's private port.
*/}}
{{- define "versitygw.standaloneIAMEndpoint" -}}
{{- if .Values.iam.standalone.endpoint }}
{{- .Values.iam.standalone.endpoint }}
{{- else if .Values.iamServer.enabled }}
{{- printf "%s:%d" (include "versitygw.iamServerPrivateServiceFullname" .) (.Values.iamServer.private.port | int) }}
{{- end }}
{{- end }}
