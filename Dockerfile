FROM python:3-slim-buster as builder

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY check_mdi.py /app/check_mdi.py

WORKDIR /app

ENTRYPOINT ["python", "check_mdi.py"]
