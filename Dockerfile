FROM wazopbx/asterisk
MAINTAINER Wazo Maintainers <dev.wazo@gmail.com>

RUN apt-get -q update && apt-get -q -y install \
    asterisk-dev \
    build-essential \
    libssl-dev
COPY . /usr/src/chan-test
WORKDIR /usr/src/chan-test

RUN make install
