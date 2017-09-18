package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	logrus_stack "github.com/Gurpartap/logrus-stack"

	"github.com/facebookgo/pidfile"
	vc "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
	"github.com/pyama86/vaz/config"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

const timeoutSec = 300

var (
	version   string
	revision  string
	goversion string
	builddate string
	builduser string
)

func init() {
	formatter := new(logrus.JSONFormatter)
	formatter.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(formatter)
	callerLevels := logrus.AllLevels
	stackLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}
	logrus.AddHook(logrus_stack.NewHook(callerLevels, stackLevels))
}

func main() {
	cli.VersionPrinter = printVersion

	app := cli.NewApp()
	app.Name = "vaz"
	app.Usage = "veeta client"
	app.Flags = flags
	app.Action = LaunchServer
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

var flags = []cli.Flag{
	cli.StringFlag{
		Name:   "config",
		Value:  "/etc/vaz.conf",
		Usage:  "config file path",
		EnvVar: "VAZ_CONFIG",
	},
	cli.StringFlag{
		Name:  "pidfile",
		Value: "/var/run/vaz.pid",
		Usage: "pid file path",
	},
	cli.StringFlag{
		Name:  "workdir",
		Value: "/var/lib/vaz",
		Usage: "work dir",
	},
}

func printVersion(c *cli.Context) {
	fmt.Printf("vaz version: %s (%s)\n", version, revision)
	fmt.Printf("build at %s (with %s) by %s\n", builddate, goversion, builduser)
}

func LaunchServer(c *cli.Context) {
	conf, err := config.NewConfig(c.GlobalString("config"))
	if err != nil {
		logrus.Fatal(err)
	}

	// set pid
	pidfile.SetPidfilePath(c.GlobalString("pidfile"))
	if err := pidfile.Write(); err != nil {
		logrus.Fatal(err)
	}
	defer removePidFile()

	hostname, err := os.Hostname()
	if err != nil {
		logrus.Fatal(err)
	}

	wd := c.GlobalString("workdir")

	found, err := exists(wd)
	if err != nil {
		log.Fatal(err)
	}

	if !found {
		if err := os.Mkdir(wd, 0777); err != nil {
			logrus.Fatal(err)
		}
	}

	util.Log = util.NewCustomLogger(vc.ServerInfo{})
	vc.Conf = vc.Config{
		CacheDBPath: path.Join(wd, "cache.db"),
		LogDir:      wd,
		ResultsDir:  wd,
		Servers: map[string]vc.ServerInfo{
			hostname: vc.ServerInfo{
				ServerName: hostname,
				Host:       "localhost",
				Port:       "local",
			},
		},
	}

	if err := scan.InitServers(timeoutSec); err != nil {
		logrus.Fatal(err)
	}

	scan.DetectPlatforms(timeoutSec)

	for {
		if err := scan.Scan(timeoutSec); err != nil {
			logrus.Fatal(err)
		}

		raw, err := ioutil.ReadFile(path.Join(wd, "current", fmt.Sprintf("%s.json", hostname)))
		if err != nil {
			logrus.Fatal(err, " can't read scan result")
		}

		sr := models.ScanResult{}
		if err := json.Unmarshal(raw, &sr); err != nil {
			logrus.Fatal(err, " scan result unmarshal error")
		}

		id, err := ioutil.ReadFile(path.Join(wd, ".id"))
		if err != nil {
			logrus.Error(err)
		}

		h := Host{
			HostID: string(id),
			Name:   hostname,
			Service: Service{
				Name: conf.Service,
			},
			ScanResult: sr,
		}

		if err := request(&h, conf); err != nil {
			logrus.Error(err, "http request error")
		} else {
			if err := writeID(path.Join(wd, ".id"), h.HostID); err != nil {
				logrus.Fatal(err, " can't write host id")
			}
		}
		time.Sleep(10 * time.Minute)
	}
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

const VEETAToken = "VEETA-TOKEN"

func request(host *Host, conf *config.Config) error {
	j, err := json.Marshal(&host)
	if err != nil {
		return err
	}
	r := "POST"
	url := conf.ServerEndpoint
	if host.HostID != "" {
		r = "PUT"
		url = fmt.Sprintf("%s/%s", url, host.HostID)
	}
	req, err := http.NewRequest(r, url, bytes.NewReader(j))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(VEETAToken, conf.Token)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bufbody := new(bytes.Buffer)
	if _, err := bufbody.ReadFrom(resp.Body); err != nil {
		return err
	}

	if err := json.Unmarshal(bufbody.Bytes(), host); err != nil {
		return err
	}
	return nil

}
func removePidFile() {
	if err := os.Remove(pidfile.GetPidfilePath()); err != nil {
		logrus.Fatalf("Error removing %s: %s", pidfile.GetPidfilePath(), err)
	}
}

type Host struct {
	HostID     string
	Name       string
	ScanResult models.ScanResult
	Service    Service
}
type Service struct {
	Name string
}

func writeID(path string, id string) error {
	return ioutil.WriteFile(path, []byte(id), os.ModePerm)
}
