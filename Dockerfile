# shepherd — identity-less IAM, firewall, rate limiter, enhancing gateway.
# Standard library only (go.mod has zero require lines); static, cgo-free image.

FROM golang:1.20-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/shepherd .

FROM alpine:3.19
RUN addgroup -S shepherd && adduser -S -G shepherd shepherd
COPY --from=build /out/shepherd /usr/local/bin/shepherd
USER shepherd
EXPOSE 8084
ENTRYPOINT ["shepherd"]