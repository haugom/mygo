# thanks for the article at https://medium.com/@lizrice/non-privileged-containers-based-on-the-scratch-image-a80105d6d341
FROM ubuntu:latest as init
RUN useradd -u 10001 scratchuser

FROM golang:1.11.4 as build
WORKDIR /go/src/app
COPY . .
RUN go get github.com/gorilla/sessions
RUN go get github.com/haugom/gwp/mygo/config
RUN go get github.com/justinas/alice
RUN go get github.com/prometheus/client_golang/prometheus/promhttp
RUN go get github.com/slok/go-prometheus-middleware
RUN go get github.com/slok/go-prometheus-middleware/negroni
RUN go get github.com/urfave/negroni
RUN go get github.com/xyproto/permissions2
RUN go get gopkg.in/boj/redistore.v1
RUN go get golang.org/x/oauth2
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"'

FROM scratch as runtime
COPY --from=build /go/src/app/app /app/server
COPY ./public/ /app/public/
COPY ./templates/ /app/templates/
EXPOSE 8081
EXPOSE 3001
WORKDIR /app
ENTRYPOINT ["/app/server"]

COPY --from=init /etc/passwd /etc/passwd
USER scratchuser
