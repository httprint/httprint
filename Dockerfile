FROM python:3

COPY requirements.txt .
RUN pip install -r requirements.txt

WORKDIR /httprint
COPY httprint/ .

ENTRYPOINT [ "python", "httprint.py" ]
