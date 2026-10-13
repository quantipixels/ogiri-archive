#!/usr/bin/env python3
"""Packaging evidence and isolated Maven consumer resolution (no mvn install)."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET
from zipfile import ZipFile, ZIP_DEFLATED

NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def reactor(directory=Path(".")):
    pom = directory / "pom.xml"
    root = ET.parse(pom).getroot()
    yield directory, root
    for module in root.findall("m:modules/m:module", NS):
        yield from reactor(directory / module.text)



def version():
    return ET.parse("pom.xml").find("m:version", NS).text


def stage():
    cache = Path("target/java/consumer-cache").resolve()
    group = cache / "com/quantipixels/ogiri"
    for directory, root in reactor():
        module = root.findtext("m:artifactId", namespaces=NS)
        destination = group / module / version()
        destination.mkdir(parents=True, exist_ok=True)
        pom = directory / "pom.xml"
        shutil.copyfile(pom, destination / f"{module}-{version()}.pom")
        if root.findtext("m:packaging", "jar", NS) != "pom":
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


def bundle():
    """Check Central's unsigned structural requirements against the deployed reactor."""
    repository = Path(sys.argv[2])
    expected = set()
    pom_count = jar_count = 0
    for directory, root in reactor():
        artifact = root.findtext("m:artifactId", namespaces=NS)
        group = root.findtext("m:groupId", namespaces=NS) or root.findtext("m:parent/m:groupId", namespaces=NS)
        release_version = root.findtext("m:version", namespaces=NS) or root.findtext("m:parent/m:version", namespaces=NS)
        assert release_version == version() and not release_version.endswith("-SNAPSHOT"), artifact
        base = Path(group.replace(".", "/")) / artifact / release_version
        stem = f"{artifact}-{release_version}"
        pom = base / f"{stem}.pom"
        deployed = ET.parse(repository / pom).getroot()
        # Metadata is explicit in every published POM, so no remote parent resolution is needed.
        for field in ("name", "description", "url", "licenses/license/name", "licenses/license/url",
                      "developers/developer/name", "scm/url", "scm/connection"):
            value = deployed.findtext("/".join("m:" + part for part in field.split("/")), namespaces=NS)
            assert value and value.strip() and "${" not in value, (artifact, field)
        paths = [pom]
        pom_count += 1
        if root.findtext("m:packaging", "jar", NS) != "pom":
            paths += [base / f"{stem}{classifier}.jar" for classifier in ("", "-sources", "-javadoc")]
            jar_count += 3
            for path in paths[1:]:
                with ZipFile(repository / path) as jar:
                    assert jar.testzip() is None and jar.namelist(), path
                    if path.name.endswith(("-sources.jar", "-javadoc.jar")):
                        suffix = ".java" if path.name.endswith("-sources.jar") else ".html"
                        assert any(n.endswith(suffix) or n == "README.md" for n in jar.namelist()), path
        for path in paths:
            data = (repository / path).read_bytes()
            expected.add(path.as_posix())
            for algorithm in ("md5", "sha1"):
                sidecar = Path(str(path) + "." + algorithm)
                assert (repository / sidecar).read_text().strip() == hashlib.new(algorithm, data).hexdigest(), sidecar
                expected.add(sidecar.as_posix())
        print(f"{artifact}: POM metadata + " + ("binary/sources/javadoc + " if len(paths) > 1 else "") + "checksums PASS")
    actual = {p.relative_to(repository).as_posix() for p in repository.rglob("*")
              if p.is_file() and not p.name.startswith("maven-metadata")}
    assert actual == expected, ("unexpected or missing deployment files", actual ^ expected)
    with ZipFile(repository / f"com/quantipixels/ogiri/ogiri/{version()}/ogiri-{version()}.jar") as jar:
        for vendor in ("postgresql", "mysql"):
            assert f"META-INF/ogiri/schema-{vendor}.sql" in jar.namelist()
        assert not any(name.startswith("db/migration/") for name in jar.namelist())
    module = "ogiri-spring-boot-autoconfigure"
    with ZipFile(repository / f"com/quantipixels/ogiri/{module}/{version()}/{module}-{version()}.jar") as jar:
        metadata = json.loads(jar.read("META-INF/spring-configuration-metadata.json"))
        assert {"ogiri.enabled", "ogiri.base-path", "ogiri.realm"} <= {p["name"] for p in metadata["properties"]}
        assert "com.quantipixels.ogiri.spring.OgiriAutoConfiguration" in jar.read("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports").decode()
    with ZipFile("target/ogiri-unsigned-bundle.zip", "w", ZIP_DEFLATED) as archive:
        for name in sorted(expected):
            archive.write(repository / name, name)
    with ZipFile("target/ogiri-unsigned-bundle.zip") as archive:
        assert set(archive.namelist()) == expected and archive.testzip() is None
    print(f"unsigned release bundle: PASS ({pom_count} POMs, {jar_count} JARs, verified checksums; signatures/Portal acceptance NOT tested)")


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
        {"stage": stage, "bundle": bundle, "database": database}[mode]()
