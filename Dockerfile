# Wyvern — passive AI-worm network sentinel
# Build:  docker build -t wyvern .
# Run (live capture needs host networking + raw-socket capabilities):
#   docker run -d --name wyvern --net=host \
#     --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -e WYVERN_INTERFACE=eth0 -e WYVERN_WEB_HOST=127.0.0.1 \
#     -v wyvern-data:/data wyvern
# Then browse http://127.0.0.1:8787
#
# No live interface? Run the safe demo instead:
#   docker run --rm -e WYVERN_WEB_HOST=0.0.0.0 -p 8787:8787 wyvern simulate --web
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Wyvern" \
      org.opencontainers.image.description="Passive AI-worm (Toronto AI worm) network sentinel" \
      org.opencontainers.image.source="https://github.com/photodoc1960/wyvern" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Dependencies first for layer caching (scapy/dpkt/Flask are pure-Python — no toolchain needed).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install the package (provides the `wyvern` entry point).
COPY pyproject.toml README.md ./
COPY wyvern ./wyvern
RUN pip install --no-cache-dir .

# Container defaults: persist to a volume, bind the dashboard to all interfaces
# *inside* the container (the operator controls exposure via -p / --net and host).
ENV WYVERN_DATA_DIR=/data \
    WYVERN_WEB_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1
VOLUME ["/data"]
EXPOSE 8787

ENTRYPOINT ["wyvern"]
CMD ["monitor", "--web"]
