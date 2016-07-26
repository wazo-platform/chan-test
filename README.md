chan-test
=========

Asterisk channel driver for testing purposes.

Installing
==========

    apt-get install build-essential asterisk-dev
    make
    make install

Usage
=====

To create a new test channel from the asterisk CLI:

    test new <exten> <context> [cid_num] [cid_name]

To answer an (outbound) channel:

    test answer <channel_id_or_name>

The commands are also available via ARI (preferred way):

    curl -i -u 'xivo:Nasheow8Eag' -d '' 'http://127.0.0.1:5039/ari/chan_test/new?context=default&exten=1001'
    curl -i -u 'xivo:Nasheow8Eag' -d '' 'http://127.0.0.1:5039/ari/chan_test/answer?id=1469040639.7'

Test channels can also be dialed:

    Dial(Test/foo)
    Dial(Test/foo/autoanswer)
