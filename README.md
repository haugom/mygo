# mygo sandbox

`mygo` is a sandbox I use to test out different go stuff.

Currently testing out different go middlewares and also testing auth0 authentication.

Below are just notes to myself.

## misc build

I ended up building a debug version with all my dependencies and dlv in it,
so I could deploy the container and exec into it and use the debugger because
I couldn't figure out why something worked on my machine but did not work on k8s.

I found out the hard way that [github.com/xyproto/permissions2](https://github.com/xyproto/permissions2)
needs a redis database. I was invoking the default .New() which expects a local redis server which I 
had forgotten to turn off then I ported the [github.com/gorilla/sessions](https://github.com/gorilla/sessions) 
to use an external redis store.

To debug this on k8s I ended up having a debug container with the debugger in it. I wasn't successful at
connecting remotely from my IDE.

## k8s setup

I've seperated the config so I don't have to look those up so often (client secret and redis key).

I split up the deployment in a debug and prod version. The prod image is build on scratch and is non-root user.

#### build image

`docker build -t haugom/mygo:$(cat ./VERSION) -f docker/Dockerfile .`

`docker push haugom/mygo:$(cat ./VERSION)`

#### build debug container

`docker build -t haugom/mygo:debug -f docker/Dockerfile.debug .`

`docker push haugom/mygo:debug`


#### build dependencies cache image

`docker build -t haugom/mygo-dependencies:latest -f docker/Dockerfile.dependencies .`

`docker push haugom/mygo-dependencies:latest`

#### deploy prod

`kontemplate template prod-deployment.yaml --var=image_tag="'$(cat ../VERSION)'" | linkerd inject - | kubectl apply -f -`
