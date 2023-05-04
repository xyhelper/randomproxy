FROM ubuntu
ENV WORKDIR /app
RUN apt-get update && \
    apt-get install -yq tzdata && \
    ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get install -yq curl && \
    apt-get install -yq ca-certificates
# COPY frontend/dist $WORKDIR/public
COPY randomproxy $WORKDIR/randomproxy
RUN chmod +x $WORKDIR/randomproxy
WORKDIR $WORKDIR
CMD ./randomproxy