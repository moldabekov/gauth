FROM scratch
COPY gauth /usr/bin/gauth
ENTRYPOINT ["/usr/bin/gauth"]
