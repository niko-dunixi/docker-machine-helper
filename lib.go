package docker_machine_helper

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/docker/docker/client"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strings"
)

// A function that will either return a
type DockerClientSupplier func() (*client.Client, error)

// Attempts to contact `docker-machine` and if it can, it will use it.
// If it can't get through to docker machine (for instance, if you have
// an actual docker installation available) it will fall back onto
// the client.NewEnvClient
func GetDockerClientEnvFallback() (*client.Client, error) {
	return GetDockerClient(client.NewEnvClient)
}

// Attempts to contact `docker-machine` and if it can, it will use it.
// If it can't get through to docker machine (for instance, if you have
// an actual docker installation available) it will fall back onto
// the your dockerClientSupplier.
func GetDockerClient(dockerClientSupplier DockerClientSupplier) (*client.Client, error) {
	dockerMachineConfig, err := getDockerMachineConfig()
	// The call to docker-machine failed, which means we can fall back
	// to our alternate client supplier
	if err != nil {
		return dockerClientSupplier()
	}
	tlsConfig, err := loadDockerMachineCerts(dockerMachineConfig.tlsCaCert)
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	httpClient := &http.Client{Transport: transport}
	return client.NewClient(dockerMachineConfig.url, dockerMachineConfig.version, httpClient, map[string]string{})
}

func getDockerMachineConfig() (DockerMachineConfig, error) {
	items, err := getOutputItemsFromDockerMachine("config")
	if err != nil {
		return DockerMachineConfig{}, err
	}
	config := parseDockerMachineOutput(items)
	versionSlice, err := getOutputItemsFromDockerMachine("version", "default")
	if err != nil {
		return config, err
	}
	if len(versionSlice) > 0 {
		config.version = versionSlice[0]
	}
	return config, nil
}

// https://forfuncsake.github.io/post/2017/08/trust-extra-ca-cert-in-go-app/
func loadDockerMachineCerts(caCertPath string) (*tls.Config, error) {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	certs, err := ioutil.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		return nil, fmt.Errorf("no certs appended, using system certs only")
	}
	// Trust the augmented cert pool in our client
	config := &tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}
	return config, nil
}

func getOutputItemsFromDockerMachine(args ...string) ([]string, error) {
	command := exec.Command("docker-machine", args...)
	output := bytes.Buffer{}
	command.Stdout = &output
	err := command.Run()
	if err != nil {
		return []string{}, err
	}
	return strings.Split(output.String(), "\n"), nil
}

func parseDockerMachineOutput(outputItems []string) (config DockerMachineConfig) {
	for _, line := range outputItems {
		scrubValue := func(value string) string {
			value = strings.TrimLeft(value, `"`)
			value = strings.TrimRight(value, `"`)
			value = strings.ReplaceAll(value, `\\`, `\`)
			return value
		}
		stuff := strings.SplitN(strings.TrimLeft(line, "-"), "=", 2)
		if len(stuff) == 0 {
			continue
		}
		key := stuff[0]
		switch key {
		case "tlsverify":
			config.tlsVerify = true
		case "tlscacert":
			config.tlsCaCert = scrubValue(stuff[1])
		case "tlscert":
			config.tlsCert = scrubValue(stuff[1])
		case "tlskey":
			config.tlsKey = scrubValue(stuff[1])
		case "H":
			config.url = scrubValue(stuff[1])
		default:
			log.Println("Unknown config:", line)
		}
	}
	return
}

type DockerMachineConfig struct {
	url       string
	version   string
	tlsVerify bool
	tlsCaCert string
	tlsCert   string
	tlsKey    string
}
