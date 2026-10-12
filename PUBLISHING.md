# Publish Ogiri

Version is `0.0.1`. The reactor publishes five coordinates under `com.quantipixels.ogiri`: `ogiri-parent` and `ogiri-bom` (POMs), plus `ogiri`, `ogiri-spring-boot-autoconfigure`, and `ogiri-spring-boot-starter` (binary, sources and Javadoc JARs with POMs). The dependency-only starter's source/Javadoc attachments contain an explanatory README. The standalone BOM aligns only the three Ogiri libraries, without importing the build parent's dependency management.

Supported runtime: Spring Boot 4.x, Java 17+, Jackson 3; current dependency baseline is Boot 4.1.1/Jackson 3.1.7. Build tools require Java 21+; the gate selects JDK 25. Boot 3/Jackson 2 are unsupported.

## Local unsigned rehearsal

```sh
mise run check:java
mise run check:java:release
```

The first command runs verification with database-tagged tests excluded. The second creates a fresh `target/release-repository.XXXXXX` directory, then uses the `release` profile with `gpg.skip=true`, `skipTests`, `verify` and the native `maven-deploy-plugin:3.1.4:deploy` goal to deploy to that local file repository. It does not call Central's deploy lifecycle publisher and needs no credentials or signing keys.

`scripts/java-artifacts.py bundle <repository>` derives the inventory from reactor POMs and checks each deployed POM's required metadata, release version, every binary/source/Javadoc attachment, MD5/SHA1 checksum contents, packaged schemas and autoconfiguration metadata/imports. It rejects missing or unexpected files and builds and reads back `target/ogiri-unsigned-bundle.zip`: currently **five POMs and nine JARs**, plus checksums. CI uploads this actual ZIP. POM-only modules require no source/Javadoc JARs. Each successful rehearsal replaces the ZIP; failed rehearsals must not be treated as evidence from an older ZIP.

This is unsigned structural evidence against [Central's requirements](https://central.sonatype.org/publish/requirements/), not signing, namespace ownership or Portal acceptance. Real release files also require valid detached `.asc` signatures. The GPG plugin is enabled only in the release profile; ordinary builds do not sign or publish.

## Authorized tag release

Before authorizing a release, run both database gates and the consumer on the exact candidate, review runtime dependency scanning and compatibility changes, and verify namespace ownership and the signing public key's availability. The tag workflow's packaging proof does not replace those integration gates.

`.github/workflows/release.yml` runs on pushed `v*` tags and requires the tag to equal `v` plus the committed POM version. It checks the repository, verifies the Java reactor without database tests, and builds/uploads the unsigned rehearsal. Only when all four existing secret names below are populated does it sign and publish:

- `OSSRH_USERNAME`: Central Portal user-token username.
- `OSSRH_PASSWORD`: Central Portal user-token password.
- `GPG_PRIVATE_KEY`: ASCII-armored signing private key.
- `GPG_PASSPHRASE`: passphrase, mapped to `MAVEN_GPG_PASSPHRASE` for Maven GPG.

These names are retained from the repository's historical release workflow; the `OSSRH_*` names now contain **Portal token credentials**, not legacy OSSRH account passwords. Missing secrets leave signing/publication inactive after verification, with a notice. Never commit credentials or keys.

`scripts/platform/publish.sh` imports the key into a private temporary GnuPG home, creates Maven settings for server ID `central` using environment references, then runs the wrapper under JDK 25 with:

```sh
-Prelease -DskipTests -Dcentral.skipPublishing=false \
  -Dcentral.autoPublish=true -Dcentral.waitUntil=published deploy
```

The Central plugin uploads signed artifacts, validates, automatically publishes, and waits for publication; any failure fails the job. The script stops its GnuPG agent on exit; the hosted runner removes the temporary keyring/settings at job completion. It does not create tags or GitHub releases. Normal profile defaults remain `central.skipPublishing=true`, `central.autoPublish=false`, `central.waitUntil=validated`. An authorized manual publisher can supply external Maven server `central` settings and a GnuPG agent, then use `-Prelease -Dcentral.skipPublishing=false deploy` to upload for validation with final publication left to the Portal.

After a real publication, verify every coordinate from a fresh Maven repository and rerun the consumer. Do not announce publication based on a local rehearsal. See [Central's Maven publisher](https://central.sonatype.org/publish/publish-portal-maven/) and [Maven GPG signing](https://maven.apache.org/plugins/maven-gpg-plugin/sign-mojo.html).
