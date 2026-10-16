FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus nginx mariadb-server mariadb-client php8.2-fpm iproute2 lsof sysstat procps rsync zip openssl lsb-release util-linux && apt-get clean
RUN ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime
CMD ["/sbin/init"]
