# Java and the JVM (Gradle, Maven; Spring Boot, jars)

Gradle's dependency verification (`gradle/verification-metadata.xml`, written by `./gradlew --write-verification-metadata sha256`) or a Maven lockfile (`lockfile.json` from maven-lockfile) pins each artifact's hash. Deploy the dependency jars in a directory the attester finds: `lib/`, `libs/`, `target/lib`, `target/dependency`, `build/install/<app>/lib`, or `WEB-INF/lib` of an unpacked war. An unpacked Spring Boot `BOOT-INF/lib` is not found on its own: list it under `installs` in the attester configuration. The jars nested inside a fat jar are not checked one by one.

Checked: every jar against its pinned hash (or Maven Central's, with `policy.unpinnedPackages`), and each JVM process for `JAVA_TOOL_OPTIONS`, `-javaagent`, `-agentpath`, JDWP, JMX without authentication, and the attach listener.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
