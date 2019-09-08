# docker-machine-helper

Do you want to use the Docker GoLang SDK, but you have to work
on a machine where you can only work with `docker-machine` as
a wrapper? This is a utility library to handle creating a docker
client and falling back upon the default if `docker-machine` isn't
installed to the machine

## Importing

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
