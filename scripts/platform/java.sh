#!/usr/bin/env bash
set -euo pipefail
mode=${1:?task mode required}
shift
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
python3 - <<'PY'
from pathlib import Path
import shutil
import xml.etree.ElementTree as ET
ns={'m':'http://maven.apache.org/POM/4.0.0'}
version=ET.parse('pom.xml').find('m:version',ns).text
cache=Path('target/java/consumer-cache').resolve()
for name in ('ogiri-parent','ogiri','ogiri-spring-boot-autoconfigure','ogiri-spring-boot-starter'):
    dest=cache/'com/quantipixels/ogiri'/name/version
    dest.mkdir(parents=True,exist_ok=True)
    shutil.copyfile('pom.xml' if name=='ogiri-parent' else f'{name}/pom.xml',dest/f'{name}-{version}.pom')
    if name in ('ogiri','ogiri-spring-boot-autoconfigure'):
        shutil.copyfile(f'{name}/target/{name}-{version}.jar',dest/f'{name}-{version}.jar')
settings=ET.Element('settings',xmlns='http://maven.apache.org/SETTINGS/1.2.0')
ET.SubElement(settings,'localRepository').text=str(cache)
profile=ET.SubElement(ET.SubElement(settings,'profiles'),'profile')
ET.SubElement(profile,'id').text='read-only-shared-cache'
ET.SubElement(ET.SubElement(profile,'activation'),'activeByDefault').text='true'
for section,entry in [('repositories','repository'),('pluginRepositories','pluginRepository')]:
    repo=ET.SubElement(ET.SubElement(profile,section),entry)
    ET.SubElement(repo,'id').text='shared-cache'
    ET.SubElement(repo,'url').text=(Path.home()/'.m2/repository').as_uri()
    for policy in ('releases','snapshots'):
        ET.SubElement(ET.SubElement(repo,policy),'checksumPolicy').text='ignore'
ET.ElementTree(settings).write('target/java/consumer-settings.xml',encoding='unicode',xml_declaration=True)
print('consumer: project artifacts staged; no mvn install')
PY
}

verify() { schemas; "${maven[@]}" verify "$@"; }
consumer_check() { stage; "${maven[@]}" "${consumer[@]}" -Pmysql -Dogiri.excludedGroups= verify; }
sbom() {
    stage
    "${maven[@]}" org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DincludeTestScope=false
    "${maven[@]}" "${consumer[@]}" -Pmysql org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom -DincludeTestScope=false
    cp target/bom.json target/library.cdx.json
    cp examples/spring-app/target/bom.json target/consumer.cdx.json
    osv-scanner scan source --format=json -L target/library.cdx.json -L target/consumer.cdx.json --output-file target/vulnerabilities.json
}
release() {
    "${maven[@]}" -Prelease -Dgpg.skip=true -DskipTests verify org.apache.maven.plugins:maven-deploy-plugin:3.1.4:deploy -DaltDeploymentRepository="rehearsal::file://$PWD/target/release-repository"
}
case "$mode" in
check) verify ;;
ci) verify -Dogiri.excludedGroups=; consumer_check ;;
full) verify -Dogiri.excludedGroups=; consumer_check; sbom; release ;;
sbom) sbom ;;
release) release ;;
benchmark) "${maven[@]}" -pl ogiri org.codehaus.mojo:exec-maven-plugin:3.5.0:java -Dexec.mainClass=com.quantipixels.ogiri.JdbcSessionsBenchmark -Dexec.classpathScope=test ;;
codeql) verify -Dmaven.test.skip=true -Dmaven.javadoc.skip=true; stage; "${maven[@]}" "${consumer[@]}" -Dmaven.test.skip=true verify ;;
staged) "${maven[@]}" spotless:check checkstyle:check ;;
fix) "${maven[@]}" spotless:apply; stage; "${maven[@]}" "${consumer[@]}" spotless:apply ;;
*) echo "unknown Java task: $mode" >&2; exit 2 ;;
esac
