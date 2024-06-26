FROM python:3-slim-buster

WORKDIR /threat-hawk-encoding

COPY requirements.txt requirements.txt

#Image python:3.9.5-slim also works # Image python:3.9.5-slim-buster also works

RUN pip install -r requirements.txt

COPY . .

WORKDIR /threat-hawk-encoding/src

CMD ["uvicorn", "main:app", "--host=0.0.0.0"]