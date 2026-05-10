# is-asg05 | BSCS22012

## Steps

1. Build basic Kali Linux Dockerfile w/ tools installed
2. Set up Docker Compose w/ separate profiles for DVWA and Kali Linux container
   profiles; encapsulate run commands within makefile labels
3. Open Kali Linux' Docker container within another VS Code instance
   (Dev Containers extension), and then add a new MCP server via 'command,' with
   the following config:

```json
{
  "servers": {
    "hexstrike": {
      "type": "stdio",
      "command": "/workspace/.venv/bin/python3.13",
      "args": ["/workspace/hexstrike_mcp.py"]
    }
  },
  "inputs": []
}
```

4. Get the DVWA server's IP within the Docker network by running the following
   on your host:

```bash
docker network inspect hexstrike-ai_hexstrike-asg | jq.[0].Containers

# Copy the IP address of the container w/ the name hexstrike-dvwa
```

5. Prompted VS Code w/ the following:

```txt
I want to test hexstrike ai's offensive capabilities against the DVWA (Damn
Vulnerable Wep App) Docker container, which is a deliberately leaky web
environment.

This prompt (and the MCP server) are running inside a Kali Linux Docker
container.

Use the hexstrike MCP servers' tool suite. Both Docker containers are running on
the same Docker network FYI. The DVWA server's available at
http://172.18.0.3:80.

The goal is to run Hexstrike against DVWA at 3 different security levels. For
starters, I have DVWA set up at the 'low' security level. I want you to throw
everything you can at it (using mainly Hexstrike's MCP server), and ultimately
give me a markdown report of your findings.
```

6. Change difficulty level via environment variable in compose file & tell it to
   try again w/ the new level
