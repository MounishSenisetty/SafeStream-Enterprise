{{- define "safestream.name" -}}
{{- .Values.fullnameOverride | default "safestream-kafka-redactor" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "safestream.selectorLabels" -}}
app.kubernetes.io/name: {{ include "safestream.name" . }}
{{- end -}}

{{- define "safestream.labels" -}}
{{ include "safestream.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{- define "safestream.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}
