FROM httpd:latest

RUN apt update && \
  apt install --yes build-essential && \
  rm --recursive --force /var/lib/apt/lists/*

ADD ./src /code

WORKDIR /code

RUN make
RUN make install