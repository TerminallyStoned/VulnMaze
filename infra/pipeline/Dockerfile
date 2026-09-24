# Ingester, digest builder and state API. Same image, different commands.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install ".[pipeline]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=UTC
COPY --from=build /install /usr/local
RUN useradd --system --uid 10001 --shell /usr/sbin/nologin vulnmaze
USER vulnmaze
WORKDIR /tmp
