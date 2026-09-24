"""Static rules for the deterministic router.

Everything here is data, not logic, so the team can review changes to the
security floor in a pull request without reading the matcher code.
"""

from __future__ import annotations

# Commands that cross a privilege or identity boundary. These are always
# answered by a fixed handler and must never reach the LLM gap-filler.
PRIVILEGE_COMMANDS: frozenset[str] = frozenset(
    {
        "sudo", "su", "doas", "pkexec", "runuser",
        "passwd", "chpasswd", "chage", "vipw", "vigr", "visudo",
        "useradd", "adduser", "usermod", "userdel", "deluser",
        "groupadd", "groupmod", "groupdel", "gpasswd", "newgrp",
        "setcap", "setfacl", "chattr",
        "insmod", "rmmod", "modprobe",
        "mount", "umount", "chroot", "nsenter", "unshare",
    }
)

# Paths whose access is a privilege boundary, whatever command touches them.
# Entries ending in "/" match the directory and everything below it.
SENSITIVE_PATHS: tuple[str, ...] = (
    "/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
    "/etc/sudoers", "/etc/sudoers.d/",
    "/etc/security/", "/etc/pam.d/",
    "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key",
    "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_dsa_key",
    "/proc/kcore", "/proc/sys/kernel/", "/dev/mem", "/dev/kmem", "/boot/",
    "/var/run/docker.sock", "/run/docker.sock",
)

# Directory names that hold credential material under any home directory
# (/root/.ssh, /home/bob/.ssh, ~/.gnupg). The attacker is usually logged in as
# root, so /root itself is their home and is not treated as sensitive.
SENSITIVE_SEGMENTS: frozenset[str] = frozenset({".ssh", ".gnupg"})

# Shell builtins and keywords Cowrie handles itself. Always deterministic.
SHELL_BUILTINS: frozenset[str] = frozenset(
    {
        ":", "[", "alias", "break", "cd", "continue", "do", "done", "echo",
        "exit", "export", "false", "help", "history", "jobs", "logout",
        "printf", "pwd", "set", "test", "true", "umask", "unset", "source",
        ".", "eval", "exec", "read", "type", "wait", "trap", "shift",
    }
)
