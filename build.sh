#!/bin/bash
docker build -t haugom/mygo:$(cat ./VERSION) -f docker/Dockerfile .
