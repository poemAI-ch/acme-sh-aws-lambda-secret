FROM python:3.11-bookworm

RUN apt-get update && apt-get install -y \
    wget curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN wget -O master.tar.gz  "https://github.com/acmesh-official/acme.sh/archive/master.tar.gz"
RUN tar xvzf master.tar.gz acme.sh-master/acme.sh && mv acme.sh-master/acme.sh . && rm -rf acme.sh-master master.tar.gz

RUN chmod +x acme.sh

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY run.py .

CMD ["python", "run.py"]
