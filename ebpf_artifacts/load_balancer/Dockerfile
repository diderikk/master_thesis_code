FROM ubuntu:22.04 as compiler

RUN apt-get update && apt-get upgrade -y && \
	apt-get install -y wget clang llvm libbpf-dev linux-headers-$(uname -r) libc6-dev-i386
	
RUN wget https://go.dev/dl/go1.22.1.linux-amd64.tar.gz && \
	rm -rf /usr/local/go && \
	tar -C /usr/local -xzf go1.22.1.linux-amd64.tar.gz && \
	rm go1.22.1.linux-amd64.tar.gz

WORKDIR /compiled

ENV PATH="${PATH}:/usr/local/go/bin"

RUN echo $PATH

COPY go.mod go.sum ./

RUN go mod download && go mod verify

COPY *.go program.bpf.c ./

COPY packet.h ../

RUN go generate && CGO_ENABLED=0 go build

FROM ubuntu:22.04

RUN apt-get update && apt-get upgrade -y

WORKDIR /app

# ENV INTERFACE_SUBSTRING wlp0s20f3

COPY --from=compiler /compiled/load-balancer-ebpf ./

CMD ["./load-balancer-ebpf"]