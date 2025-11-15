FROM ubuntu:latest

RUN apt-get update 
RUN apt-get install -y clang llvm libelf-dev libpcap-dev build-essential make curl git cmake
RUN apt-get install -y linux-tools-common

RUN curl -L https://go.dev/dl/go1.25.4.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

RUN git clone --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git && \
    cp linux/include/uapi/linux/bpf* /usr/include/linux/

# TODO: make libbpf-dev a submodule
RUN apt-get install -y libbpf-dev

WORKDIR /app
COPY . .
ENV GOPATH=/go
ENV PATH="$GOPATH/bin:$PATH"

RUN make