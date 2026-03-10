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
