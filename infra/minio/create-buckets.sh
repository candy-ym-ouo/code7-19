#!/bin/sh
set -eu
MINIO_USER="${MINIO_ROOT_USER:-minioadmin}"
MINIO_PASSWORD="${MINIO_ROOT_PASSWORD:-minioadmin}"
until mc alias set local http://minio:9000 "$MINIO_USER" "$MINIO_PASSWORD"; do sleep 1; done
mc mb --ignore-existing local/${MINIO_QUARANTINE_BUCKET:-map-quarantine}
mc mb --ignore-existing local/${MINIO_PUBLIC_BUCKET:-map-public}
mc mb --ignore-existing local/${MINIO_EXPORT_BUCKET:-map-exports}
mc anonymous set none local/${MINIO_QUARANTINE_BUCKET:-map-quarantine}
mc anonymous set download local/${MINIO_PUBLIC_BUCKET:-map-public}
# 合规导出桶只允许服务端凭证访问；浏览器仅通过短期签名 URL 下载。
mc anonymous set none local/${MINIO_EXPORT_BUCKET:-map-exports}
# 导出归档保留 30 天；到期由合规调度器删除对象并留存删除证明，生命周期规则仅作对象层兜底。
mc ilm rule add --expire-days ${EXPORT_RETENTION_DAYS:-30} local/${MINIO_EXPORT_BUCKET:-map-exports} 2>/dev/null || echo "warning: MinIO did not accept export bucket lifecycle rule"
mc cors set local/${MINIO_QUARANTINE_BUCKET:-map-quarantine} /init/cors.xml || echo "warning: MinIO did not accept bucket CORS; configure CORS at the reverse proxy if browser uploads are blocked"
mc cors set local/${MINIO_PUBLIC_BUCKET:-map-public} /init/cors.xml || echo "warning: MinIO did not accept bucket CORS; configure CORS at the reverse proxy if browser uploads are blocked"
echo "MinIO buckets initialized"
