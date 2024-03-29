# docker-machine-helper

Do you want to use the [Docker GoLang SDK](https://docs.docker.com/develop/sdk/), but
you have to work on a machine where you can only work with `docker-machine` as a wrapper?
This is a utility library to handle creating a docker client and falling back upon the
default if `docker-machine` isn't installed to the machine

## Use it!

```
go get github.com/paul-nelson-baker/docker-machine-helper
```

And import in your project:
```go
import (
    dockerMachineHelper "github.com/paul-nelson-baker/docker-machine-helper"
)

func main() {
    dockerClient, err := dockerMachineHelper.GetDockerClientEnvFallback()
    if err != nil {
        log.Fatalln(err)
    }
    // ... use dockerClient like normal
}
```

## Under the Hood

So what's happening under the hood? Not a _whole_ lot, but just enough to waste a
whole day's worth of productivity trying to solve the puzzle.

In a typical docker installation has two parts. The cli tool and the engine itself.
The cli tool is nothing more than a rest client that sends and receives commands to
and from the engine.

When a system doesn't have the minimum requirements necessary to run docker, you
can instead run [Docker Toolbox](https://docs.docker.com/toolbox/overview/). It
isn't optimal, but it lets you use docker by running docker from within a virtual
box installation instead of on the machine itself.

When it's running in this manner, docker-machine exposes a port from the guest vm
to the host machine that is running (in this case your machine) and you can now
use the docker cli the same way you would normally. However, because you're using
the API you have to set up communication yourself (which is what this library does).

In order to communicate with this running instance of docker, we run the following
`docker-machine config` then consume and parse what it writes to standard-out. This
tells us a number of things:

1. The docker URL
2. The location of:
    * The CA Certificate
    * The client certificate
    * The client key

We will need all this in order to communicate with the docker instance, as the URL
is encrypted and this is a self signed certificate. Fortunately, it's relatively
easy to tell Go to use all this information. Once Go trusts the certificate authority
and the client certificate, we can make a restful call to Docker and find out the
exact version its API supports. It's just a matter of plugging and chugging all the 
known values, and then Bob's your uncle!
