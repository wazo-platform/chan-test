FROM quintana/asterisk
MAINTAINER dev+docker@proformatique.com

ADD . /usr/src/chan-test
WORKDIR /usr/src/chan-test

RUN make install
