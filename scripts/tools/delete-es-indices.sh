set -e

ES_URL="${ELASTICSEARCH_URL:-${ES_URL:-https://elasticsearch.mahdixak.ir}}"
ES_URL="${ES_URL%/}"
ES_USER="${ES_USERNAME:-${ES_USER:-}}"
ES_PASS="${ES_PASSWORD:-${ES_PASS:-}}"

for index in audit-logs audit-logs-flat; do
  if [[ -n "$ES_USER" ]]; then
    status=$(curl -s -o /dev/null -w "%{http_code}" -u "${ES_USER}:${ES_PASS}" -X DELETE "${ES_URL}/${index}")
  else
    status=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "${ES_URL}/${index}")
  fi
  if [[ "$status" == "200" ]]; then
    echo "Deleted index: ${index}"
  elif [[ "$status" == "404" ]]; then
    echo "Index already missing: ${index}"
  else
    echo "Failed to delete ${index} (HTTP ${status})"
    exit 1
  fi
done
echo "Done."
