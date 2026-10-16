FROM python:3.15.0-slim-trixie
COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /usr/local/bin/uv
WORKDIR /app
COPY . .
RUN uv sync --locked --no-dev --extra server --no-editable --python /usr/local/bin/python \
    && rm /usr/local/bin/uv \
    && apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && setcap cap_net_bind_service=+ep /usr/local/bin/python3.15 \
    && apt-get purge -y libcap2-bin && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data wildburrow \
    && mkdir -p /data && chown wildburrow /data
ENV PATH=/app/.venv/bin:$PATH WILDBURROW_DATA_DIR=/data
USER wildburrow
VOLUME /data
EXPOSE 80 443 2222
ENTRYPOINT ["wildburrow"]
CMD ["serve"]
