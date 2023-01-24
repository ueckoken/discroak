FROM golang:1.19.5 AS Builder

ARG VERSION=snapshot
WORKDIR /app
COPY go.sum go.mod ./
RUN go mod download
COPY . ./
RUN make build

FROM gcr.io/distroless/static-debian11:nonroot AS Runner

COPY --from=Builder --chown=nonroot:nonroot /app/discroak /discroak
ENTRYPOINT [ "/discroak" ]
