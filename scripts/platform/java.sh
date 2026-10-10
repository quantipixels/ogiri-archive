#!/usr/bin/env bash
set -euo pipefail

# Owned by the Spring builder. Never install artifacts into the shared ~/.m2.
mode=${1:?task mode required}
shift
maven=(mvn --batch-mode --no-transfer-progress)
consumer=(-s "$PWD/target/java/consumer-settings.xml" -f examples/spring-app/pom.xml)

verify() {
    "${maven[@]}" verify
}

consumer_check() {
    python scripts/java-artifacts.py stage
    "${maven[@]}" "${consumer[@]}" -Pmysql verify
    python scripts/java-artifacts.py evidence
}

schema() {
    local version jar
    version=$(python scripts/java-artifacts.py version)
    jar="ogiri/target/ogiri-$version.jar"
    case "${OGIRI_TEST_DATABASE:?set OGIRI_TEST_DATABASE to postgresql or mysql}" in
    postgresql)
        export PGPASSWORD=${OGIRI_TEST_JDBC_PASSWORD:?}
        read -r db_host db_port db_name < <(python scripts/java-artifacts.py database)
        psql -h "$db_host" -p "$db_port" -U "${OGIRI_TEST_JDBC_USER:?}" -d "$db_name" -v ON_ERROR_STOP=1 -c 'DROP TABLE ogiri_sessions, ogiri_subject_locks'
        unzip -p "$jar" META-INF/ogiri/schema-postgresql.sql | psql -h "$db_host" -p "$db_port" -U "$OGIRI_TEST_JDBC_USER" -d "$db_name" -v ON_ERROR_STOP=1
        ;;
    mysql)
        export MYSQL_PWD=${OGIRI_TEST_JDBC_PASSWORD:?}
        read -r db_host db_port db_name < <(python scripts/java-artifacts.py database)
        mysql -h "$db_host" -P "$db_port" -u "${OGIRI_TEST_JDBC_USER:?}" "$db_name" -e 'DROP TABLE ogiri_sessions, ogiri_subject_locks'
        unzip -p "$jar" META-INF/ogiri/schema-mysql.sql | mysql -h "$db_host" -P "$db_port" -u "$OGIRI_TEST_JDBC_USER" "$db_name"
        ;;
    *)
        echo 'OGIRI_TEST_DATABASE must be postgresql or mysql' >&2
        exit 2
        ;;
    esac
}

sbom() {
    python scripts/java-artifacts.py stage
    "${maven[@]}" org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DincludeTestScope=false
    "${maven[@]}" "${consumer[@]}" -Pmysql org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DincludeTestScope=false
    cp target/bom.json target/library.cdx.json
    cp examples/spring-app/target/bom.json target/consumer.cdx.json
    osv-scanner scan source --format=json -L target/library.cdx.json -L target/consumer.cdx.json --output-file target/vulnerabilities.json
}

release() {
    "${maven[@]}" -Prelease -Dgpg.skip=true -DskipTests verify org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy -DaltDeploymentRepository="rehearsal::file://$PWD/target/release-repository"
    python scripts/java-artifacts.py bundle
}

case "$mode" in
check) verify ;;
ci)
    verify
    schema
    consumer_check
    ;;
full)
    verify
    schema
    consumer_check
    sbom
    release
    ;;
sbom) sbom ;;
release) release ;;
benchmark)
    "${maven[@]}" -pl ogiri org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=com.quantipixels.ogiri.JdbcSessionsBenchmark -Dexec.classpathScope=test
    ;;
codeql)
    "${maven[@]}" -Dmaven.test.skip=true -Dmaven.javadoc.skip=true verify
    python scripts/java-artifacts.py stage
    "${maven[@]}" "${consumer[@]}" -Dmaven.test.skip=true verify
    ;;
staged | fix)
    echo 'Java formatter not configured yet; staged whitespace is checked by check:staged'
    ;;
*)
    echo "unknown Java task: $mode" >&2
    exit 2
    ;;
esac
