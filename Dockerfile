FROM python:3.11-bookworm

RUN apt-get update && apt-get install -y \
    wget curl \
    && rm -rf /var/lib/apt/lists/*

RUN wget -O acme_sh_install.sh  "https://get.acme.sh"

RUN chmod +x acme_sh_install.sh

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY run.py .

CMD ["python", "run.py"]
