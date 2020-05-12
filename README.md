# Docker Mailproxy

This docker image uses Dovecot Proxy feature to create a mail reverse proxy for IMAP3S, POP3S and SMTPS. We use SNI to identify different configuration. Per domain a different backend service is called. All authentication is forwarded to the backend service.
