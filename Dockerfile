FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
	pip install -r requirements.txt

COPY scraper.py .
COPY libhub_client_rs.so .

CMD python scraper.py
