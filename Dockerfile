FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

COPY . /workspace
WORKDIR /workspace

RUN python3 -m venv .venv && \
    . .venv/bin/activate && \
    pip install -r requirements.txt

ENV PATH="/workspace/.venv/bin:$PATH"
