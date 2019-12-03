FROM wazopbx/asterisk

RUN apt-get -q update && apt-get -q -y install \
    asterisk-dev \
    build-essential \
    libssl-dev \
    asterisk-sounds-main \
    asterisk-moh-opsound-wav \
    # wazo-calld integration tests need fuser
    psmisc
COPY . /usr/src/chan-test
WORKDIR /usr/src/chan-test

RUN make install
