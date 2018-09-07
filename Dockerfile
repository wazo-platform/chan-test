FROM wazopbx/asterisk

RUN apt-get -q update && apt-get -q -y install \
    asterisk-dev \
    build-essential \
    libssl-dev \
    asterisk-sounds-main
COPY . /usr/src/chan-test
WORKDIR /usr/src/chan-test

RUN make install
