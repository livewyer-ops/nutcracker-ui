FROM scratch

ADD assets /assets
ADD html /html
COPY etc /etc
ADD https://curl.haxx.se/ca/cacert.pem /etc/ssl/certs/cacert.pem
ADD nutcracker-ui /

CMD [ "/nutcracker-ui" ]
ENTRYPOINT [ "/nutcracker-ui" ]