FROM busybox
ENV a=1
USER 1
RUN touch /tmp/user-1
RUN /bin/echo test
USER 2
RUN touch /tmp/user-2
USER 3:1
RUN touch /tmp/user-3-1
RUN ls -al /tmp
USER 0