#!/usr/bin/env bash
# Invoked only by the tag-release workflow after verification and credential checks.
set -euo pipefail
: "${CENTRAL_USERNAME:?}" "${CENTRAL_PASSWORD:?}" "${GPG_PRIVATE_KEY:?}" "${MAVEN_GPG_PASSPHRASE:?}"
: "${RUNNER_TEMP:?}" "${GITHUB_REF_NAME:?}"
[[ "$GITHUB_REF_NAME" == "v$(python3 scripts/java-artifacts.py version)" ]]
umask 077
export GNUPGHOME
GNUPGHOME=$(mktemp -d "$RUNNER_TEMP/ogiri-gpg.XXXXXX")
settings="$GNUPGHOME/settings.xml"
# The hosted runner discards RUNNER_TEMP at job completion; stop the agent immediately.
trap 'gpgconf --kill gpg-agent || true' EXIT
printf '%s' "$GPG_PRIVATE_KEY" | gpg --batch --import
unset GPG_PRIVATE_KEY
cat >"$settings" <<'XML'
<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">
  <servers><server><id>central</id>
    <username>${env.CENTRAL_USERNAME}</username>
    <password>${env.CENTRAL_PASSWORD}</password>
  </server></servers>
</settings>
XML
mise exec java@25.0.2 -- "$PWD/ogiri/mvnw" --batch-mode --no-transfer-progress \
    -s "$settings" -Prelease -DskipTests \
    -Dogiri.checks.dir="$PWD/ogiri/checks" \
    -Dcentral.skipPublishing=false -Dcentral.autoPublish=true -Dcentral.waitUntil=published deploy
