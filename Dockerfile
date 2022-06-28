FROM python:3.10-slim@sha256:2bac43769ace90ebd3ad83e5392295e25dfc58e58543d3ab326c3330b505283d as build

# Hardened based on this guide (not complete, not tested)
# https://snyk.io/blog/best-practices-containerizing-python-docker/

RUN mkdir /code

RUN apt-get update
RUN apt-get install -y \
    --no-install-recommends \
    build-essential gcc

WORKDIR /code
RUN python -m venv /code/venv

RUN /code/venv/bin/python -m pip install --upgrade pip

ENV PATH="/code/venv/bin:$PATH"

COPY ./requirements.txt /code/requirements.txt

RUN /usr/local/bin/python -m pip install --upgrade pip

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

FROM python:3.10-slim@sha256:2bac43769ace90ebd3ad83e5392295e25dfc58e58543d3ab326c3330b505283d

RUN groupadd -g 990 python && \
    useradd -r -u 990 -g python python

WORKDIR /code/venv
COPY --chown=python:python --from=build /code/venv .

USER 990
ENV PATH="/code/venv/bin:$PATH"

COPY --chown=python:python ./app /code/app
COPY --chown=python:python ./settings /code/settings

WORKDIR /code
#ENV APP_PORT=8001 # get the value from the ini file

# set permissions to allow non privildged user to bing to port < 1024
# RUN setcap cap_net_bind_service=ep /code/venv/bin/python

CMD python app/main_api.py
#CMD uvicorn app.main_api:app --host "0.0.0.0" --port ${APP_PORT}
# CMD gunicorn --bind 0.0.0.0:${APP_PORT} --worker-class uvicorn.workers.UvicornWorker --workers 4 app.main:app

HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD curl --fail http://localhost:${APP_PORT}/health || exit 1
