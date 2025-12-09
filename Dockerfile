ARG BUILD_FROM
FROM ${BUILD_FROM}

ENV LANG C.UTF-8

RUN apk add --no-cache python3 py3-pip py3-setuptools py3-wheel

RUN apk add --no-cache curl
COPY rootfs/ /
WORKDIR /usr/src/app

COPY app.py index.html requirements.txt ./
RUN python3 -m venv /usr/src/app/venv \
	&& /usr/src/app/venv/bin/python -m pip install --upgrade pip setuptools wheel \
	&& if [ -f requirements.txt ]; then /usr/src/app/venv/bin/pip install --no-cache-dir -r requirements.txt; fi

RUN if [ -f /etc/services.d/a1mini/run ]; then chmod +x /etc/services.d/a1mini/run || true; fi \
    && if [ -f /etc/cont-init.d/10-a1mini ]; then chmod +x /etc/cont-init.d/10-a1mini || true; fi

EXPOSE 5000
