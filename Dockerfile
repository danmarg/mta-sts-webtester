FROM alpine:latest

MAINTAINER Daniel Margolis <dan@af0.net>

WORKDIR "/opt"

ADD .docker_build/smtp-sts-webtester /opt/bin/smtp-sts-webtester
ADD ./templates /opt/templates
ADD ./static /opt/static

CMD ["/opt/bin/smtp-sts-webtester"]

