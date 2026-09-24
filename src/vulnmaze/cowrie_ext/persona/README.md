# Persona outputs

Fixed outputs for commands where Cowrie's built-in answer is a known
fingerprint. `{hostname}` is replaced with the honeypot hostname.

The persona is **Debian 12 (bookworm)**, matching Cowrie 3.0.14's defaults
(kernel 6.1.0-21-amd64, OpenSSH_9.2p1 Debian-2+deb12u3), so the fewest
things need changing.

These files are best-effort placeholders. Before deploying, capture the real
output from a Debian 12 machine and paste it in:

    docker run --rm -it debian:12 bash -c 'apt-get update -qq && apt-get install -y -qq sudo >/dev/null; sudo -l; sudo -V'

Override the directory at runtime with VULNMAZE_PERSONA_DIR.
