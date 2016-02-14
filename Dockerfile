FROM golang:latest

MAINTAINER Dmitry Kravtsov <idkravitz@gmail.com>


RUN apt-get update && apt-get install -y build-essential libssl-dev \
	&& useradd -r -m tram
USER tram
WORKDIR /home/tram

RUN cp ~/.profile ~/.oldprofile && curl https://raw.githubusercontent.com/creationix/nvm/v0.30.2/install.sh | bash \
	&& . ~/.profile && nvm install 5.6.0 && nvm use 5.6.0 \
	&& npm install jade jstransformer-markdown-it --global \
	&& mkdir -p bin pkg src/github.com/kravitz/tram_api

ENV GOPATH /home/tram
RUN go get gopkg.in/mgo.v2 && go get golang.org/x/crypto/bcrypt && go get github.com/streadway/amqp

USER root

RUN apt-get remove -y build-essential libssl-dev && apt-get autoremove -y && apt-get autoclean -y && \
	apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD . src/github.com/kravitz/tram_api/
ADD www/ www/
RUN chown -R tram:tram www src

USER tram

RUN . ~/.profile && nvm use 5.6.0 && jade www && mv ~/.oldprofile ~/.profile && rm -rf ~/.nvm
RUN go install github.com/kravitz/tram_api
EXPOSE 8080

ENTRYPOINT ["./bin/tram_api"]
