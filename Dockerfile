# Build the jar first: ./mvnw -B verify (or package -DskipTests), then: docker build -t mcp-credential-broker:dev .
FROM eclipse-temurin:25-jre-alpine@sha256:b7528962e65d43064d8a8b67ba175367896bc948363ea2d3fcd7f10d34e1f048

RUN addgroup -S broker && adduser -S -G broker -H -h /app broker
WORKDIR /app
COPY --chown=root:root target/mcp-credential-broker.jar /app/app.jar

USER broker
EXPOSE 8443
# All configuration comes from MCP_* environment variables (application.yml, README).
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
