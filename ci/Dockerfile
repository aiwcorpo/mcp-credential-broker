# Image for running ci/run.sh where no JDK is installed. The tests start containers, so run it with the Docker socket
# mounted (-v /var/run/docker.sock:/var/run/docker.sock) and the checkout as /work.
FROM maven:3.9.12-eclipse-temurin-25
RUN apt-get update && apt-get install -y --no-install-recommends git perl docker.io && rm -rf /var/lib/apt/lists/*
WORKDIR /work
CMD ["./ci/run.sh"]
