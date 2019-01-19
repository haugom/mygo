#!/bin/bash
docker build -t haugom/mygo:$(cat ./VERSION) -f docker/Dockerfile .
docker push haugom/mygo:$(cat ./VERSION)