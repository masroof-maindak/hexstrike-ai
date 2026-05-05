FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv
COPY . /workspace
WORKDIR /workspace

RUN python3 -m venv .venv && \
    . .venv/bin/activate && \
    pip install -r requirements.txt

ENV PATH="/workspace/.venv/bin:$PATH"

RUN apt-get install -y \
    curl \
    ca-certificates \
    git \
    wget \
    unzip \
    build-essential \
    nmap \
    masscan \
    amass \
    subfinder \
    nuclei \
    fierce \
    dnsenum \
    theharvester \
    responder \
    netexec \
    enum4linux-ng \
    gobuster \
    feroxbuster \
    dirsearch \
    ffuf \
    dirb \
    nikto \
    sqlmap \
    wpscan \
    arjun \
    paramspider \
    wafw00f \
    hydra \
    john \
    hashcat \
    medusa \
    patator \
    crackmapexec \
    hash-identifier \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
