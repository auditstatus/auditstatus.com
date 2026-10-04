{{- define "attester.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "attester.labels" -}}
app.kubernetes.io/name: {{ include "attester.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "attester.selector" -}}
app.kubernetes.io/name: {{ include "attester.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}


{{- /* The image by digest when image.digest is set (tag@digest keeps the tag readable). */ -}}
{{- define "attester.image" -}}
{{- $image := printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- with .Values.image.digest -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .) -}}
{{- fail "image.digest must be sha256:<64 hex digits>" -}}
{{- end -}}
{{- $image = printf "%s@%s" $image . -}}
{{- end -}}
{{- $image -}}
{{- end -}}

{{- define "attester.port" -}}
{{- $port := int .Values.port -}}
{{- if or (lt $port 1) (gt $port 65535) (ne (toString $port) (toString .Values.port)) -}}
{{- fail "port must be a TCP port number" -}}
{{- end -}}
{{- $port -}}
{{- end -}}
