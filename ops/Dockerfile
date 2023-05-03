FROM python:3.7.4-stretch

ENV PROJECT_DIR /app

COPY . ${PROJECT_DIR}

WORKDIR ${PROJECT_DIR}
RUN pip install -r ops/requirements.txt
