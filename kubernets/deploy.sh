#!/bin/bash
kontemplate template prod-deployment.yaml --var=image_tag="$(cat ../VERSION)" | linkerd inject - | kubectl apply -f -
