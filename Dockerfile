FROM python:3.10-bookworm

ENV STAGING_KEY=RANDOM DEBIAN_FRONTEND=noninteractive DOTNET_CLI_TELEMETRY_OPTOUT=1
ARG PYTHON_VERSION=3.10.11
RUN dpkg --add-architecture i386

RUN  apt update \
  && apt upgrade -y \
  && apt install -y --no-install-recommends build-essential wget wine wine32:i386 \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

# set the def shell for ENV
SHELL ["/bin/bash", "-c"]
RUN wget -q https://packages.microsoft.com/config/debian/11/packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
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

RUN mkdir -p /wine/python
RUN cd /wine/python \
    && wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/python-${PYTHON_VERSION}-embed-win32.zip \
    && unzip python-*.zip \
    && rm -f python-*.zip

ENV WINEPREFIX /wine
ENV WINEPATH Z:\\wine\\python\\Scripts;Z:\\wine\\python
ENV PYTHONHASHSEED=123

RUN cd /wine/python \
  && rm python*._pth \
  && wget https://bootstrap.pypa.io/get-pip.py

RUN wineboot --init
RUN wineboot --restart
RUN cd /wine/python \
    && wine python --version \
    && wine python get-pip.py \
    && wine pip install pyinstaller pyarmor tinyaes

ENTRYPOINT ["./ps-empire"]
CMD ["server"]
