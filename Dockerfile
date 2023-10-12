# image base
FROM python:3.11-bookworm-slim
RUN apt update && apt upgrade -y
RUN pip install --upgrade pip

# env setup
ENV STAGING_KEY=RANDOM DEBIAN_FRONTEND=noninteractive DOTNET_CLI_TELEMETRY_OPTOUT=1

# set the def shell for ENV
SHELL ["/bin/bash", "-c"]
RUN wget -q https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    apt update && \
    apt install -qq -y \
    --no-install-recommends \
    apt-transport-https \
    dotnet-sdk-6.0 \
    libicu-dev \
    powershell \
    python3-dev \
    python3-pip \
    sudo \
    xclip \
    zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /empire

COPY pyproject.toml poetry.lock /empire/

RUN pip install poetry \
    --disable-pip-version-check && \
    poetry config virtualenvs.create false && \
    poetry install --no-root

COPY . /empire

RUN sed -i 's/use: mysql/use: sqlite/g' empire/server/config.yaml
RUN mkdir -p /usr/local/share/powershell/Modules && \
    cp -r ./empire/server/data/Invoke-Obfuscation /usr/local/share/powershell/Modules
RUN rm -rf /empire/empire/server/data/empire*

ENTRYPOINT ["./ps-empire"]
CMD ["server"]
