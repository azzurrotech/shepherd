FROM golang:1.20-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o shepherd-server ./main.go

EXPOSE 8081

CMD ["/app/shepherd-server"]
