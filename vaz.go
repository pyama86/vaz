package main

import (
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
)

func main() {
	host, err := os.Hostname()
	if err != nil {
		panic(err)
	}
	util.Log = util.NewCustomLogger(config.ServerInfo{})
	timeoutSec := 300
	config.Conf = config.Config{
		CacheDBPath: filepath.Join("/tmp/", "cache.db"),
		LogDir:      "/tmp",
		ResultsDir:  "/tmp",
		Servers: map[string]config.ServerInfo{
			host: config.ServerInfo{
				ServerName: host,
				Host:       "localhost",
				Port:       "local",
			},
		},
	}

	if err := scan.InitServers(timeoutSec); err != nil {
		panic(err)
	}

	scan.DetectPlatforms(timeoutSec)

	if err := scan.Scan(timeoutSec); err != nil {
		panic(err)
	}
}
