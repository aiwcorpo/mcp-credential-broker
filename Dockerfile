# Build the jar first: ./mvnw -B verify (or package -DskipTests), then: docker build -t mcp-credential-broker:dev .
FROM eclipse-temurin:25-jre-alpine@sha256:b7528962e65d43064d8a8b67ba175367896bc948363ea2d3fcd7f10d34e1f048
LABEL org.opencontainers.image.source="https://github.com/aiwcorpo/mcp-credential-broker" \
      org.opencontainers.image.licenses="Apache-2.0"

# gid 10001 is fixed: the PostgreSQL and Redis containers of deploy/compose.yaml join it (group_add) to read the files init shares with them.
RUN addgroup -S -g 10001 broker && adduser -S -G broker -H -h /app broker \
    && mkdir -p /secrets/broker /secrets/postgres /secrets/redis \
    && chown broker:broker /secrets/broker /secrets/postgres /secrets/redis
WORKDIR /app
COPY --chown=root:root target/mcp-credential-broker.jar /app/app.jar

USER broker
EXPOSE 8443
# All configuration comes from MCP_* environment variables (application.yml, README). /secrets/*: written by "init" on the first
# start (deploy/compose.yaml); a new named volume takes this owner from the image.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-XX:+ExitOnOutOfMemoryError", "-jar", "/app/app.jar"]
