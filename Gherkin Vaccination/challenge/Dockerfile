FROM ubuntu:22.04

RUN apt update -y && apt install -y netcat python3-flask

COPY app app
COPY flag.txt flag.txt

WORKDIR /app

EXPOSE 80

CMD ["flask", "run", "-h", "0.0.0.0", "-p", "80"]
