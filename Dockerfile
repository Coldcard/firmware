FROM gcc:11.5.0-bullseye

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    make \
    python3 python3-venv python3-pip \
    swig \
    libpcsclite-dev pcscd \
    pkg-config \
    libffi-dev \
    xterm \
    autoconf automake libtool m4 

WORKDIR /build

RUN git clone --depth 1 --recursive \
    https://github.com/Coldcard/firmware.git

WORKDIR /build/firmware/unix

# Build mpy-cross
RUN make -C ../external/micropython/mpy-cross

# Build simulator & tools
RUN make setup
RUN make ngu-setup
RUN make

# remove unnecessary git files
RUN find /build/firmware -name ".git" -type d -prune -exec rm -rf '{}' +