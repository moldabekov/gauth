FROM scratch
COPY gorelease_ex /usr/bin/gauth
ENTRYPOINT ["/usr/bin/gauth"]
