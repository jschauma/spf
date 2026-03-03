# From @Techbrunch via https://github.com/jschauma/spf/issues/2
FROM debian:bookworm-slim

RUN apt update
RUN apt install -y libjson-perl libnet-dns-perl libnet-netmask-perl libsocket6-perl build-essential git
RUN git clone https://github.com/jschauma/spf/ && cd spf && make install

ENTRYPOINT [ "spf" ]
