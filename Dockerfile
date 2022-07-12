## compile proxy-init utility
FROM --platform=$BUILDPLATFORM golang:1.18.4-alpine3.16 as golang
WORKDIR /build

# cache dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# build
COPY . .
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o /out/linkerd2-proxy-init -mod=readonly -ldflags "-s -w" -v

## package runtime
FROM --platform=$TARGETPLATFORM alpine:3.16.0
RUN apk add iptables ip6tables libcap
RUN touch /run/xtables.lock && chmod 0666 /run/xtables.lock
RUN setcap cap_net_raw,cap_net_admin+eip /sbin/xtables-legacy-multi
COPY LICENSE /linkerd/LICENSE
COPY --from=golang /out/linkerd2-proxy-init /usr/local/bin/proxy-init
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/proxy-init
ENTRYPOINT ["/usr/local/bin/proxy-init"]

USER 65534
