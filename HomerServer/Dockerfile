FROM alpine:3.7
RUN apk update && apk add python py2-pip ansible openssh-client

WORKDIR /opt/homer/

COPY ansible/. /opt/ansible/
COPY homer/. /opt/homer/
RUN pip install -r /opt/homer/requirements.txt
RUN /usr/bin/ssh-keygen -q -t rsa -N '' -f /root/.ssh/id_rsa
