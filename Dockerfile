FROM scratch

ADD assets /assets
ADD html /html
ADD nutcracker-ui /

CMD [ "/nutcracker-ui" ]
ENTRYPOINT [ "/nutcracker-ui" ]