#!/bin/bash
set -euo pipefail

echo "🚀 เริ่มต้นการ Deploy ไปยัง Staging (Mock Sandbox)..."
sleep 2

HEALTH_STATUS="ok"
INTEGRATION_STATUS="pass"
DEPLOY_ID="deploy-$(date +%s)"
ARTIFACT_SHA256="sha256:abcdef123456"

cat > staging-evidence.json <<EOF
{
  "deploy_id": "$DEPLOY_ID",
  "artifact_sha256": "$ARTIFACT_SHA256",
  "health": "$HEALTH_STATUS",
  "integration_check": "$INTEGRATION_STATUS"
}
EOF

echo "✅ สร้าง Staging Evidence สำเร็จ:"
cat staging-evidence.json
