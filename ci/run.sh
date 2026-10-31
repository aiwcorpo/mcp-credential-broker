#!/usr/bin/env bash
# Single CI entry point (M5-5): every CI system, the container image of ci/Dockerfile and a developer's shell call this
# script and nothing else. .gitlab-ci.yml, Jenkinsfile and .github/workflows/ci.yml are thin wrappers around it. Needs
# bash, git, JDK 25 and either a filled ~/.m2 with the mcp-contracts artifacts or MCP_MAVEN_REPOSITORY_URL (+ _USER,
# _PASSWORD) pointing at the registry that holds them.
#
#   ci/run.sh                 verify (default)
#   ci/run.sh verify          hygiene checks, then unit and integration tests (mvnw clean verify)
#   ci/run.sh hygiene         only the text checks of the sources (non-ASCII quotes and spaces, tool traces)
#   ci/run.sh image           verify, then build the container image mcp-credential-broker:m5-<short sha> from the jar
#                             (needs a clean checkout, so that the tag names the code it holds)
#
# The integration tests start PostgreSQL, Redis and OpenBao with Testcontainers and, in MultiInstanceIntegrationTest,
# extra broker JVMs on ports 18712-18717, so a container runtime must be reachable (a Docker socket mounted into the CI
# container, or DOCKER_HOST) and those ports must be free. Without a runtime the integration test classes fail.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ -z "${JAVA_HOME:-}" ]] && ! command -v java >/dev/null; then
  echo "ci/run.sh: no JDK; set JAVA_HOME to a JDK 25 or use the image of ci/Dockerfile" >&2
  exit 1
fi

mvnw() {
  if [[ -n "${MCP_MAVEN_REPOSITORY_URL:-}" ]]; then
    ./mvnw -B -s .ci/settings.xml "$@"
  else
    ./mvnw -B "$@"
  fi
}

tracked_sources() {
  git ls-files -z --cached --others --exclude-standard -- '*.java' '*.md' '*.xml' '*.yml' '*.yaml' '*.properties' '*.json' '*.sh' 'Jenkinsfile' 'Dockerfile' 'ci/Dockerfile' ':!:ci/run.sh'
}

# The two checks of the house style: characters that give away generated text, and phrases left by tools.
hygiene() {
  local failed=0
  if tracked_sources | xargs -0 perl -ne 'if (/[\x{00A0}\x{200B}\x{202F}\x{FEFF}\x{2018}\x{2019}\x{201C}\x{201D}\x{2026}]/) { print "$ARGV:$.: $_"; $bad = 1 } END { exit($bad ? 1 : 0) }' -CSD; then
    :
  else
    echo "ci/run.sh: non-ASCII quotes, spaces or ellipsis found (above)" >&2
    failed=1
  fi
  if tracked_sources | xargs -0 grep -niE 'as an ai|generated with|co-authored-by: claude|lorem ipsum|your-api-key|example\.com' -- ; then
    echo "ci/run.sh: tool traces or placeholders found (above)" >&2
    failed=1
  fi
  return "$failed"
}

# A build that ran no test proves nothing (a skipped module, a broken surefire setup), so it fails.
verify() {
  hygiene
  mvnw clean verify
  local reports
  reports="$(find target/surefire-reports -name 'TEST-*.xml' 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$reports" -eq 0 ]]; then
    echo "ci/run.sh: no test reports in target/surefire-reports; zero tests is a failure" >&2
    exit 1
  fi
}

image() {
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "ci/run.sh image: the working tree has uncommitted changes; the tag would not name the code in the image" >&2
    exit 1
  fi
  verify
  local tag
  tag="mcp-credential-broker:m5-$(git rev-parse --short HEAD)"
  docker build -t "$tag" .
  echo "ci/run.sh: built $tag"
}

case "${1:-verify}" in
  verify) verify ;;
  hygiene) hygiene ;;
  image) image ;;
  *) echo "usage: ci/run.sh [verify|hygiene|image]" >&2; exit 2 ;;
esac
