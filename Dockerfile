FROM golang:latest

MAINTAINER Dmitry Kravtsov <idkravitz@gmail.com>

# http proxy support
RUN apt-get update && apt-get install -y nodejs npm
RUN [ -n "$http_proxy" ] && apt-get update && apt-get install -y corkscrew && \
	echo "ProxyCommand corkscrew $http_proxy %h %p" | sed 's/:/ /g' >> /etc/ssh/config || echo 'No proxy'

RUN npm install jade --global
RUN ln -s /usr/bin/nodejs /usr/local/bin/node
RUN useradd -r -m tram
USER tram
WORKDIR /home/tram

RUN mkdir -p bin pkg src/github.com/kravitz/tram_api
ENV GOPATH /home/tram
RUN go get gopkg.in/mgo.v2 && go get golang.org/x/crypto/bcrypt && go get github.com/streadway/amqp

USER root

RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
ADD . src/github.com/kravitz/tram_api/
ADD www/ www/
RUN chown -R tram:tram www src

USER tram

RUN jade www
RUN go install github.com/kravitz/tram_api
EXPOSE 8080

ENTRYPOINT ["./bin/tram_api"]
