FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive container=docker

RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv docker.io python3 python3-yaml \
    nftables iproute2 iptables curl ca-certificates openssl openssh-server \
    procps kmod liblz4-1 libcap-ng0 libnetfilter-queue1 libnfnetlink0 \
    libjansson4 libyaml-0-2 libpcre2-8-0 libpcap0.8t64 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && systemctl disable docker.service docker.socket containerd.service \
    && systemctl mask systemd-remount-fs.service dev-hugepages.mount \
       sys-fs-fuse-connections.mount

COPY daemon.json /etc/docker/daemon.json

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
