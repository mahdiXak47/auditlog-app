k{{/*
Chart name (from Chart.yaml).
*/}}
{{- define "audit-logs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Full name: release-name-chart-name (used for resource names).
*/}}
{{- define "audit-logs.fullname" -}}
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
ServiceAccount name (for deployment spec).
*/}}
{{- define "audit-logs.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (printf "%s" (include "audit-logs.fullname" .)) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
