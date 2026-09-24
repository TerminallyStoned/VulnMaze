"""Commands Cowrie 3.0.14 answers itself (Python handlers plus bundled txtcmds).

Generated with ``python scripts/export_known_commands.py`` against the pinned
Cowrie version. Regenerate it whenever you bump Cowrie. Inside the running
honeypot the router asks Cowrie directly instead (see cowrie_ext.hooks), so
this list is only used for offline classification of datasets and in tests.
"""

from __future__ import annotations

COWRIE_VERSION = "3.0.14"

KNOWN_COMMANDS: frozenset[str] = frozenset(
    """
    adduser apt apt-get awk base64 bash busybox cat chattr chgrp chmod chown
    chpasswd clear cp crontab curl cut date dd df dget dig dir dmesg du echo
    egrep emacs enable env ethtool exit export fgrep find finger free ftpget
    gcc gcc-4.7 getconf git grep groups halt head history hostname id ifconfig
    iptables jobs kill killall killall5 last locate logout ls lscpu lspci make
    mkdir mount mv nano nc netcat netstat nohup nproc passwd perl php pico ping
    pkill poweroff printf ps pwd python reboot reset rm rmdir scp service set sh
    shutdown sleep ssh stty su sudo sync tail tar tee test tftp top touch true
    ulimit umask uname uniq unset unzip uptime useradd users vi vim vipw w wc
    wget which who whoami yes yum
    """.split()
)
