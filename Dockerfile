FROM python:3.13-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
        amd64) kubectl_arch="amd64" ;; \
        arm64) kubectl_arch="arm64" ;; \
        *) echo "unsupported kubectl architecture: $arch" >&2; exit 1 ;; \
    esac \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/${kubectl_arch}/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && rm kubectl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY sentinel /app/sentinel
COPY scripts /app/scripts

RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "sentinel.webapp:app", "--host", "0.0.0.0", "--port", "8000"]
