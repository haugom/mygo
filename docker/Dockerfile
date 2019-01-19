# thanks for the article at https://medium.com/@lizrice/non-privileged-containers-based-on-the-scratch-image-a80105d6d341
FROM ubuntu:latest as init
RUN useradd -u 10001 scratchuser

FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM haugom/mygo-dependencies:latest as build
WORKDIR /go/src/app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux govvv build -a -ldflags '-extldflags "-static"'

FROM scratch as runtime
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /go/src/app/app /app/server
COPY ./public/ /app/public/
COPY ./templates/ /app/templates/
EXPOSE 8081
EXPOSE 3001
WORKDIR /app
ENTRYPOINT ["/app/server"]

COPY --from=init /etc/passwd /etc/passwd
USER scratchuser
