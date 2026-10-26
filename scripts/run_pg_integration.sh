#!/usr/bin/env bash
#
# Run the DBHarness integration suite against a throwaway Dockerized PostgreSQL.
#
#   scripts/run_pg_integration.sh
#
# It starts a postgres:16 container, waits for it to accept connections, points
# DBHARNESS_TEST_PG_DSN at it, runs `pytest tests/integration`, and tears the
# container down again (even on failure). Requires Docker and a Python env with
# the project installed with its dev + postgres extras:
#
#   pip install -e ".[dev,postgres]"
#
set -euo pipefail

CONTAINER="dbharness-pg-itest"
IMAGE="postgres:16-alpine"
PORT="${DBHARNESS_PG_PORT:-55432}"     # non-default to avoid clashing with a local PG
PASSWORD="dbharness"
DB="dbharness"

cleanup() {
  echo "==> Removing container ${CONTAINER}"
  docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup  # in case a previous run left one behind

echo "==> Starting ${IMAGE} on port ${PORT}"
docker run -d --name "${CONTAINER}" \
  -e POSTGRES_PASSWORD="${PASSWORD}" \
  -e POSTGRES_DB="${DB}" \
  -p "${PORT}:5432" \
  "${IMAGE}" >/dev/null

echo "==> Waiting for Postgres to be ready"
for i in $(seq 1 30); do
  if docker exec "${CONTAINER}" pg_isready -U postgres -d "${DB}" >/dev/null 2>&1; then
    echo "    ready after ${i}s"
    break
  fi
  sleep 1
  if [ "${i}" -eq 30 ]; then echo "Postgres did not become ready" >&2; exit 1; fi
done

export DBHARNESS_TEST_PG_DSN="postgresql://postgres:${PASSWORD}@localhost:${PORT}/${DB}"
echo "==> DBHARNESS_TEST_PG_DSN=${DBHARNESS_TEST_PG_DSN}"

echo "==> Running integration tests"
PYTHONPATH=src python -m pytest tests/integration -v "$@"
