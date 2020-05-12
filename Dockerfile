FROM debian:buster-slim

ARG VCS_REF
ARG VCS_VERSION

LABEL maintainer="Thoralf Rickert-Wendt"  \
    org.label-schema.name="mailproxy" \
    org.label-schema.description="A fullstack but simple mailproxy (smtps, imaps, pop3s)" \
    org.label-schema.url="https://github.com/trickert76/mailproxy" \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.vcs-url="https://github.com/trickert76/mailproxy" \
    org.label-schema.version=$VCS_VERSION \
    org.label-schema.schema-version="1.0"

ARG DEBIAN_FRONTEND=noninteractive

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN \
  apt-get update -q --fix-missing && \
  apt-get -y upgrade && \
  apt-get -y install --no-install-recommends \
    apt-transport-https \
    binutils \
    procps \
    bzip2 \
    ca-certificates \
    fail2ban \
    iptables \
    locales \
    supervisor \
    opendkim \
    opendkim-tools \
    dovecot-core \
    dovecot-imapd \
    dovecot-ldap \
    dovecot-lmtpd \
    dovecot-managesieved \
    dovecot-pop3d \
    dovecot-sieve \
    dovecot-solr \
    && \
  apt-get autoclean && \
  rm -rf /var/lib/apt/lists/* && \
  rm -rf /usr/share/locale/* && \
  rm -rf /usr/share/man/* && \
  rm -rf /usr/share/doc/* && \
  touch /var/log/auth.log && \
  update-locale

#RUN mkdir -p /usr/local/bin
#COPY bin/* /usr/local/bin/.
#RUN chmod +x /usr/local/bin/*

COPY supervisor/supervisord.conf /etc/supervisor/supervisord.conf
COPY supervisor/conf.d/* /etc/supervisor/conf.d/

WORKDIR /

EXPOSE 25 587 143 465 993 110 995 4190

CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
