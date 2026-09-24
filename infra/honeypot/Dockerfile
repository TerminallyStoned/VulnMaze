# Cowrie (pinned) + the VulnMaze router plugin. No compilers, no shell tools
# beyond the base image, runs as an unprivileged user.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[honeypot]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=UTC
COPY --from=build /install /usr/local
RUN useradd --system --uid 999 --home-dir /cowrie --shell /usr/sbin/nologin cowrie \
 && mkdir -p /cowrie/etc /cowrie/var/log/cowrie /cowrie/var/lib/cowrie/downloads /cowrie/var/lib/cowrie/tty \
 && chown -R cowrie:cowrie /cowrie/var \
 # Rebuild Twisted's plugin cache now; the root filesystem is read-only at runtime.
 && python -c "from twisted.plugin import IPlugin, getPlugins; list(getPlugins(IPlugin))"
USER cowrie
WORKDIR /cowrie
EXPOSE 2222
# -n: stay in foreground; -l -: log to stdout; empty pidfile: nothing to write.
CMD ["twistd", "--umask=0022", "-n", "--pidfile=", "-l", "-", "vulnmaze"]
