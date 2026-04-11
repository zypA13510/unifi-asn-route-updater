FROM python:3.13-trixie AS build

ARG PIPX_HOME=/opt/pipx

RUN set -x \
    && apt-get update \
    && apt-get install  -y --no-install-recommends \
        pipx \
        python3.13-dev \
        build-essential \
    && pipx ensurepath \
    && pipx install aggregate6

FROM python:3.13-slim-trixie AS final

RUN set -x \
    && apt-get update \
    && apt-get install  -y --no-install-recommends \
        curl \
        jq \
        pipx

COPY --from=build /opt/pipx/venvs/aggregate6 /opt/pipx/venvs/aggregate6
COPY --chmod=755 ui-update-asn-routes.sh /usr/local/bin/ui-update-asn-routes

USER nobody

ENV PATH="/opt/pipx/venvs/aggregate6/bin:$PATH"

WORKDIR /home
ENTRYPOINT ["ui-update-asn-routes"]
CMD []
