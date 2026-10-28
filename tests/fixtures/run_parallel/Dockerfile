FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends bats \
    && rm -rf /var/lib/apt/lists/*

COPY smoke.bats /opt/smoke.bats
ENTRYPOINT ["bash", "-c", "exec bats --formatter tap --filter \"$1\" /opt/smoke.bats", "--"]
