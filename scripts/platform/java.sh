#!/usr/bin/env bash
set -euo pipefail
mode=${1:-check}
if (($#)); then shift; fi
export OGIRI_TEST_DATABASE=${OGIRI_TEST_DATABASE:-postgresql}
if [[ "$OGIRI_TEST_DATABASE" == mysql ]]; then
    export OGIRI_TEST_JDBC_URL=${OGIRI_TEST_JDBC_URL:-"jdbc:mysql://localhost:${OGIRI_MYSQL_PORT:-3306}/ogiri_test?allowPublicKeyRetrieval=true&sslMode=DISABLED&socketTimeout=10000"}
else
    export OGIRI_TEST_JDBC_URL=${OGIRI_TEST_JDBC_URL:-"jdbc:postgresql://localhost:${OGIRI_PG_PORT:-5432}/ogiri_test?socketTimeout=10"}
fi
export OGIRI_TEST_JDBC_USER=${OGIRI_TEST_JDBC_USER:-ogiri}
export OGIRI_TEST_JDBC_PASSWORD=${OGIRI_TEST_JDBC_PASSWORD:-ogiri}
test_java=$(mise where java@temurin-17.0.17+10)
maven=(mise exec java@25.0.2 -- "$PWD/ogiri/mvnw" --batch-mode --no-transfer-progress "-Dogiri.test.jvm=$test_java/bin/java" "-Dogiri.checks.dir=$PWD/ogiri/checks")
consumer=(-s "$PWD/target/java/consumer-settings.xml" -f "$PWD/examples/spring-app/pom.xml")

schemas() {
    for engine in postgresql mysql; do
        for kind in ogiri users; do
            cmp "contracts/schema/$kind-$engine.sql" "ogiri/src/main/resources/META-INF/ogiri/$kind-$engine.sql"
        done
        cmp "contracts/schema/ogiri-$engine.sql" "ogiri/src/main/resources/META-INF/ogiri/schema-$engine.sql"
    done
    echo 'contract schema drift: PASS'
}

stage() {
    python3 scripts/java-artifacts.py stage
}

verify() {
    schemas
    "${maven[@]}" verify "$@"
}
consumer_check() {
    stage
    "${maven[@]}" "${consumer[@]}" -Pmysql -Dogiri.excludedGroups= verify
}
sbom() {
    stage
    "${maven[@]}" org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DincludeTestScope=false
    "${maven[@]}" "${consumer[@]}" -Pmysql org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DincludeTestScope=false
    cp target/bom.json target/library.cdx.json
    cp examples/spring-app/target/bom.json target/consumer.cdx.json
    osv-scanner scan source --format=json -L target/library.cdx.json -L target/consumer.cdx.json --output-file target/vulnerabilities.json
}
release() {
    mkdir -p target
    local repository
    repository=$(mktemp -d "$PWD/target/release-repository.XXXXXX")
    "${maven[@]}" -Prelease -Dgpg.skip=true -DskipTests verify org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy -DaltDeploymentRepository="rehearsal::file://$repository"
    python3 scripts/java-artifacts.py bundle "$repository"
}

case "$mode" in
check) verify ;;
ci)
    verify -Dogiri.excludedGroups=
    consumer_check
    ;;
full)
    verify -Dogiri.excludedGroups=
    consumer_check
    sbom
    release
    ;;
sample)
    stage
    "${maven[@]}" "${consumer[@]}" -DskipTests verify spring-boot:repackage
    ;;
sbom) sbom ;;
release) release ;;
benchmark) "${maven[@]}" -pl ogiri org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=com.quantipixels.ogiri.JdbcSessionsBenchmark -Dexec.classpathScope=test ;;
codeql)
    verify -Dmaven.test.skip=true -Dmaven.javadoc.skip=true
    stage
    "${maven[@]}" "${consumer[@]}" -Dmaven.test.skip=true verify
    ;;
staged) "${maven[@]}" spotless:check checkstyle:check ;;
fix)
    "${maven[@]}" spotless:apply
    stage
    "${maven[@]}" "${consumer[@]}" spotless:apply
    ;;
*)
    echo "unknown Java task: $mode" >&2
    exit 2
    ;;
esac
