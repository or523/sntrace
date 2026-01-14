FROM mcr.microsoft.com/devcontainers/cpp:1-debian-12

# Install additional packages if needed
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends strace
