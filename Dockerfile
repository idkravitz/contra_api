FROM golang:latest

MAINTAINER Dmitry Kravtsov <idkravitz@gmail.com>

# http proxy support
RUN [ -n "$http_proxy" ] && apt-get update && apt-get install -y corkscrew && \
	echo "ProxyCommand corkscrew $http_proxy %h %p" | sed 's/:/ /g' >> /etc/ssh/config || echo 'No proxy'

RUN useradd -r -m tram
USER tram
WORKDIR /home/tram

RUN mkdir bin src pkg src/tram src/tram-commons
ENV GOPATH /home/tram
RUN go get gopkg.in/mgo.v2 && go get golang.org/x/crypto/bcrypt && go get github.com/streadway/amqp

USER root
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
USER tram

ADD src/tram/api/ src/tram/api/
ADD src/tram-commons/lib/ src/tram-commons/lib/
ADD www/ www/

RUN go install tram/api
EXPOSE 8080

ENTRYPOINT ["./bin/api"]