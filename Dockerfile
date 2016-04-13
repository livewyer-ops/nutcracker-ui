FROM scratch

ADD assets /
ADD html /
ADD nutcracker-ui /

CMD [ "/nutcracker-ui" ]
ENTRYPOINT [ "/nutcracker-ui" ]