#!/usr/bin/env python3
"""Packaging evidence and isolated Maven consumer resolution (no mvn install)."""
import json
import os
from pathlib import Path
import shutil
import sys
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from zipfile import ZipFile, ZIP_DEFLATED

NS = {"m": "http://maven.apache.org/POM/4.0.0"}
MODULES = ("ogiri", "ogiri-spring-boot-starter")


def version():
    return ET.parse("pom.xml").find("m:version", NS).text


def stage():
    cache = Path("target/java/consumer-cache").resolve()
    group = cache / "com/quantipixels/ogiri"
    for module in ("ogiri-parent", *MODULES):
        destination = group / module / version()
        destination.mkdir(parents=True, exist_ok=True)
        pom = Path("pom.xml") if module == "ogiri-parent" else Path(module) / "pom.xml"
        shutil.copyfile(pom, destination / f"{module}-{version()}.pom")
        if module != "ogiri-parent":
            shutil.copyfile(Path(module) / f"target/{module}-{version()}.jar", destination / f"{module}-{version()}.jar")
    # Read the shared cache as a file repository; all writes go to this worktree.
    settings = ET.Element("settings", xmlns="http://maven.apache.org/SETTINGS/1.2.0")
    ET.SubElement(settings, "localRepository").text = str(cache)
    profile = ET.SubElement(ET.SubElement(settings, "profiles"), "profile")
    ET.SubElement(profile, "id").text = "read-only-shared-cache"
    ET.SubElement(ET.SubElement(profile, "activation"), "activeByDefault").text = "true"
    for section, entry in (("repositories", "repository"), ("pluginRepositories", "pluginRepository")):
        repository = ET.SubElement(ET.SubElement(profile, section), entry)
        ET.SubElement(repository, "id").text = "shared-cache"
        ET.SubElement(repository, "url").text = (Path.home() / ".m2/repository").as_uri()
        for policy in ("releases", "snapshots"):
            ET.SubElement(ET.SubElement(repository, policy), "checksumPolicy").text = "ignore"
    ET.ElementTree(settings).write("target/java/consumer-settings.xml", encoding="unicode", xml_declaration=True)
    print("consumer artifacts staged in target/java/consumer-cache; shared Maven artifacts untouched")


def evidence():
    results = []
    for module in (*MODULES, "examples/spring-app"):
        reports = list(Path(module).glob("target/surefire-reports/TEST-*.xml"))
        assert reports, f"no test reports: {module}"
        for report in reports:
            root = ET.parse(report).getroot()
            counts = {key: int(root.get(key, 0)) for key in ("tests", "failures", "errors", "skipped")}
            assert counts["tests"] and not any(counts[key] for key in ("failures", "errors", "skipped")), (module, counts)
            results.append({"module": module, "suite": root.get("name"), **counts})
    for module in MODULES:
        for classifier, suffix in (("sources", ".java"), ("javadoc", ".html")):
            with ZipFile(f"{module}/target/{module}-{version()}-{classifier}.jar") as jar:
                assert any(name.endswith(suffix) for name in jar.namelist()), module
    with ZipFile(f"ogiri/target/ogiri-{version()}.jar") as jar:
        for vendor in ("postgresql", "mysql"):
            assert f"META-INF/ogiri/schema-{vendor}.sql" in jar.namelist()
        assert not any(name.startswith("db/migration/") for name in jar.namelist())
    with ZipFile(f"ogiri-spring-boot-starter/target/ogiri-spring-boot-starter-{version()}.jar") as jar:
        metadata = json.loads(jar.read("META-INF/spring-configuration-metadata.json"))
        names = {prop["name"] for prop in metadata["properties"]}
        assert {"ogiri.enabled", "ogiri.base-path", "ogiri.endpoints-enabled", "ogiri.lifetime", "ogiri.maximum-sessions", "ogiri.realm"} <= names
        assert "com.quantipixels.ogiri.spring.OgiriAutoConfiguration" in jar.read("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports").decode()
    Path("target/verification.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"package evidence: PASS ({sum(item['tests'] for item in results)} tests, zero failures/errors/skips)")


def bundle():
    repository = Path("target/release-repository")
    with ZipFile("target/ogiri-unsigned-bundle.zip", "w", ZIP_DEFLATED) as archive:
        for path in sorted(repository.glob("com/**/*")):
            if path.is_file() and not path.name.startswith("maven-metadata"):
                archive.write(path, path.relative_to(repository))
    with ZipFile("target/ogiri-unsigned-bundle.zip") as archive:
        names = archive.namelist()
        assert len([name for name in names if name.endswith(".pom")]) == 3
        assert len([name for name in names if name.endswith(".jar")]) == 6
        for name in names:
            if name.endswith((".pom", ".jar")):
                assert name + ".sha1" in names and name + ".md5" in names, name
    print("unsigned release bundle: PASS (3 POMs, 6 JARs, checksum sidecars)")


def database():
    url = urlsplit(os.environ["OGIRI_TEST_JDBC_URL"].removeprefix("jdbc:"))
    default = {"postgresql": 5432, "mysql": 3306}
    assert url.scheme in default and url.hostname and url.path.strip("/"), "invalid test JDBC URL"
    print(url.hostname, url.port or default[url.scheme], url.path.strip("/"))


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "version":
        print(version())
    else:
        {"stage": stage, "evidence": evidence, "bundle": bundle, "database": database}[mode]()
