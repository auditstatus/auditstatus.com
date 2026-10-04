# The attester as a container image, for the Kubernetes DaemonSet (see
# charts/auditstatus-attester).  Built by the release workflow from the
# release's single executables:
#
#   docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=2.0.0 .
#
# The image holds the attester, crictl (to identify containers through the
# CRI) and tpm2-tools.  It runs `auditstatus serve` on the pod's loopback
# interface; the verifier reaches it with `kubectl port-forward`.

# Pinned by digest (the multi-platform index), so a rebuild cannot pick up a
# different base; Dependabot proposes updates.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

ARG TARGETARCH
ARG CRICTL_VERSION=v1.31.1
ARG CRICTL_SHA256_AMD64=0a03ba6b1e4c253d63627f8d210b2ea07675a8712587e697657b236d06d7d231
ARG CRICTL_SHA256_ARM64=cd70f9b2f75c9619f40450d4b6e2c74aaab619917da517eff6787b442f8b0e56

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl tpm2-tools \
  && case "$TARGETARCH" in amd64) sum="$CRICTL_SHA256_AMD64" ;; arm64) sum="$CRICTL_SHA256_ARM64" ;; *) exit 1 ;; esac \
  && curl -fsSL --proto '=https' -o /tmp/crictl.tar.gz "https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${TARGETARCH}.tar.gz" \
  && echo "${sum}  /tmp/crictl.tar.gz" | sha256sum --check --strict \
  && tar -xzf /tmp/crictl.tar.gz -C /usr/local/bin crictl \
  && rm /tmp/crictl.tar.gz \
  && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY release/ /tmp/release/
RUN case "$TARGETARCH" in amd64) arch=x64 ;; arm64) arch=arm64 ;; esac \
  && install -m 0755 "/tmp/release/auditstatus-linux-${arch}" /usr/local/bin/auditstatus \
  && rm -rf /tmp/release \
  && auditstatus version

ENTRYPOINT ["auditstatus"]
CMD ["serve", "--config", "/etc/auditstatus/config.yml", "--listen", "127.0.0.1:8740"]
