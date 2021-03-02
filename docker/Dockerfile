# Dockerfile to build firmware binary
#
# based on <https://blog.feabhas.com/2017/12/introduction-docker-embedded-developers-part-4-reducing-docker-image-size/>
# and <https://github.com/lucaszanella/coldcard-docker>
#
FROM alpine:3.13.2

WORKDIR /work

#ADD . /work

RUN apk add --no-cache git python3 py-pip musl-dev make && \
    apk add gcc-arm-none-eabi newlib-arm-none-eabi --update-cache \
        --repository http://dl-3.alpinelinux.org/alpine/edge/testing/

RUN ln -s /usr/bin/python3 /usr/bin/python

RUN git clone --recursive https://github.com/Coldcard/firmware.git

WORKDIR /work/firmware

RUN git submodule update --init

WORKDIR /work/firmware/stm32

RUN make setup

# TODO ... more
#RUN make

#RUN sed -i '29 s/^/        #/' /home/project/firmware/unix/frozen-modules/pyb.py \
#&& sed -i "31,32 s/# *//" /home/project/firmware/unix/frozen-modules/pyb.py


#COPY docker_init.sh /home/project/docker_init.sh
