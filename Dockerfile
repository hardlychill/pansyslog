FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY pansyslog/ pansyslog/
COPY config.yaml /etc/pansyslog/config.yaml

ENV PYTHONUNBUFFERED=1

VOLUME /data

EXPOSE 8787

CMD ["python", "-m", "pansyslog"]
