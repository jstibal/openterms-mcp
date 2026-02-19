FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask pyjwt cryptography pyyaml

COPY . .

EXPOSE 5000

ENV FREE_MODE=true

CMD ["python", "run.py"]
