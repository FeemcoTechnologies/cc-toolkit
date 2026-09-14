# ── CC Toolkit — Kali Linux + JupyterLab ──────────────────────────────────
# Jupyter workspace that doubles as a Kali box: use the Jupyter web UI or its
# built-in Terminal for a root shell with Kali's command-line toolset.
#
# Build:
#   docker build -t cc-jupyter-kali:latest docker/jupyter-kali
#   (started automatically via docker-compose --profile with-jupyter)
#
# Install more tools at runtime (root shell):
#   apt-get update && apt-get install -y kali-tools-top10
#
# The default apt mirror can be overridden at build time:
#   docker build --build-arg KALI_MIRROR=https://mirrors.ocf.berkeley.edu/kali ...
# Required: KALI_MIRROR is the repo root already ending in /kali.
# ──────────────────────────────────────────────────────────────────────────

# Fully-qualified: podman without unqualified registries needs docker.io/
FROM docker.io/kalilinux/kali-rolling

# Canonical Kali repo; --build-arg override (e.g. a geometrically closer or
# non-flaky mirror) is supported if the default node is slow/overloaded.
ARG KALI_MIRROR=http://http.kali.org/kali

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    PYTHONUNBUFFERED=1

# Base + lightweight offensive CLI toolkit (small, fast to build).
# Add more later via apt (see header).
RUN sed -i "s|http://http.kali.org/kali|${KALI_MIRROR}|g" \
        /etc/apt/sources.list.d/kali.sources \
        /etc/apt/sources.list \
        /etc/apt/sources.list.d/*.list 2>/dev/null || true \
    && apt-get update -o Acquire::Retries=5 -o Acquire::http::Timeout=45 \
    && apt-get install -y --no-install-recommends \
        bash-completion \
        curl wget \
        dnsutils iproute2 iputils-ping net-tools \
        jq ripgrep \
        netcat-openbsd nmap tcpdump \
        hydra sqlmap \
        python3 python3-pip \
        tmux vim unzip xz-utils git \
    && rm -rf /var/lib/apt/lists/*

# Kali ships an externally-managed Python env; use the standard container escape hatch.
RUN python3 -m pip install --no-cache-dir --break-system-packages jupyterlab

RUN mkdir -p /work
WORKDIR /work
EXPOSE 8888

# Roots of the Jupyter process (and its terminal) default to root on Kali.
# JUPYTER_TOKEN empty => no auth (local convenience); set it for exposed hosts.
CMD ["sh", "-c", "jupyter lab --ip=0.0.0.0 --port=8888 --no-browser --allow-root \
     --ServerApp.root_dir=/work --ServerApp.allow_root=True \
     --ServerApp.token=${JUPYTER_TOKEN} --ServerApp.password='' \
     --ServerApp.allow_origin='*' --ServerApp.disable_check_xsrf=True \
     --ServerApp.tornado_settings='{\"headers\":{\"Content-Security-Policy\":\"frame-ancestors *\"}}'"]