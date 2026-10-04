# Java and the JVM

Build the application in CI or on the server, and deploy the dependency jars as files in a directory such as `lib/` or `libs/`. Jars are copied from the repository unchanged, so each jar's SHA-256 must be one the build pinned. The attester hashes every jar in each dependency directory and reads its Maven coordinates, and inspects each JVM process. The verifier compares each jar's hash with Gradle's dependency verification metadata or a Maven lockfile at the deployed commit. The application's own jar is build output: compare it with a build the verifier runs, or deploy it in an attested release.


## What gets verified

| What                        | Reference                                                                                                                                                                                                                                                                                  | Check                 |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------- |
| Tracked files               | The deployed commit, on the audited branch                                                                                                                                                                                                                                                 | `source`              |
| Each dependency jar         | The SHA-256 pinned for that file name in `gradle/verification-metadata.xml` (`sha256` and `also-trust`) or in `lockfile.json` from maven-lockfile                                                                                                                                          | `packages:maven`      |
| Jars the build does not pin | The jar Maven Central serves for the coordinates in the jar's `META-INF/maven/.../pom.properties` (`policy.unpinnedPackages`, default `warn`)                                                                                                                                              | `packages:maven`      |
| The application jar         | A build of the same commit (`build`), or an attested release ([binaries](binaries.md))                                                                                                                                                                                                     | `build` or `artifact` |
| Each process                | `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`; `-javaagent`, `-agentpath` and `-agentlib`; JDWP; `-Xbootclasspath/a:` and `/p:`; `-Djava.system.class.loader`; JMX remote; attach settings and an active attach listener; `-XX:OnError`; `CLASSPATH` without `-cp`; memory maps | `process`             |


## Requirements

* Commit pinned hashes for every dependency:
  * Gradle: `./gradlew --write-verification-metadata sha256` writes `gradle/verification-metadata.xml`.
  * Maven: generate `lockfile.json` with maven-lockfile, using SHA-256 checksums.
* Deploy dependencies as separate jar files in one of the directories the attester looks in:
  * `lib/` or `libs/` in the service root
  * `build/install/<app>/lib` (Gradle `installDist`)
  * `target/lib` or `target/dependency` (Maven copy and assembly plugins)
  * `target/<app>/WEB-INF/lib` or `build/libs/<app>/WEB-INF/lib` (unpacked wars)
* For another directory, such as an unpacked Spring Boot `BOOT-INF/lib`, list it under `installs` in the attester configuration.
* Keep the application's own jar outside the dependency directory, for example in `build/libs/`, and compare it through `build`.
* Keep other files out of the dependency directory.


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /srv/app/current
    user: app
    ecosystems: [maven]
```

For a directory the attester does not look in:

```yaml
    installs:
      - ecosystem: maven
        dir: BOOT-INF/lib
```

A relative `dir` is resolved against the service root.


## Verifier configuration

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
    # The application jar itself is built by CI: attest its manifest, or
    # rebuild it here:
    # build:
    #   command: ./gradlew --no-daemon bootJar
    #   outputs: [build/libs/*.jar]
servers:
  - name: app1
    host: app1.example.com
```

Set `lockfiles.maven` when the metadata is not at its usual path, and `references.registries.maven` for a Maven Central mirror. See [configuration](../configuration.md).


## Build and deploy

The tested setup pins `commons-lang3-3.17.0.jar` in `gradle/verification-metadata.xml`, ignores `lib/` in `.gitignore`, copies the jar into `lib/` after the checkout, and runs:

```sh
java -cp lib/commons-lang3-3.17.0.jar Main.java
```

* A reproduced build must give the same bytes. For Gradle, turn on reproducible archives (`preserveFileTimestamps = false`, `reproducibleFileOrder = true` on archive tasks); for Maven, set `project.build.outputTimestamp`.
* A Spring Boot fat jar holds its dependencies inside the jar, where they are not scanned one by one. Either compare the whole jar as build output, or unpack it and list `BOOT-INF/lib` under `installs`.
* Restart the JVM after each deploy. A tracked file or build output changed after the process started fails (`policy.modifiedAfterStart`).


## Common findings

| Finding                                                                                      | Cause and fix                                                                                                                                  |
| -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `Jars the build does not pin were compared with Maven Central`                               | Write verification metadata or a Maven lockfile and commit it.                                                                                 |
| `the jar differs from the one the build pinned`                                              | A different or modified jar was deployed. Deploy the jars the build resolved.                                                                  |
| `the build pins no jar of this name, and the jar names no Maven coordinates`                 | A jar with no pin and no `pom.properties`, often the application jar in the dependency directory. Move it out, and compare it through `build`. |
| `the jar differs from Maven Central's for its coordinates`                                   | An unpinned jar that is not the published one. Pin it, and deploy the published jar.                                                           |
| `Links or other entries named like jars, which the JVM may load, that are not regular files` | A link named `*.jar` in the directory. Replace it with the file.                                                                               |
| `Other files next to the jars`                                                               | Non-jar files in the dependency directory. Move them.                                                                                          |
| `No lockfile at the deployed commit pins these packages`                                     | No verification metadata or Maven lockfile at the commit.                                                                                      |
| `jvm-javaagent`, `jvm-native-agent`, `debugger` (process)                                    | An agent or JDWP in the JVM options or `JAVA_TOOL_OPTIONS`. Remove it in production.                                                           |


## Limits

* Dependencies inside a fat jar are not checked one by one.
* A jar is matched by file name in the Gradle metadata and in maven-lockfile, not by group.
* The JDK is explained as code only when a distribution package owns it or its hash is pinned under `executables`; see [the verifier guide](../verifier.md).

See [how it works](../how-it-works.md) for the overall flow.
