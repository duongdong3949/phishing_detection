FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libpcap-dev --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8000

CMD ["uvicorn", "network_crawler:app", "--host", "0.0.0.0", "--port", "8000"]