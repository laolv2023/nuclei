FROM python:3.12-slim

RUN apt-get update && apt-get install -y wget unzip && \
    wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_Linux_amd64.zip -O /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip && \
    apt-get remove -y wget unzip && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

RUN nuclei -update-templates

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

CMD ["python", "-m", "app.main"]
