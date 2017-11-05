package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"time"

	logrus_stack "github.com/Gurpartap/logrus-stack"

	"github.com/facebookgo/pidfile"
	"github.com/pyama86/vaz/config"
	"github.com/pyama86/vaz/scan"
	"github.com/pyama86/vaz/util"
	"github.com/pyama86/vaz/veeta"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var (
	version   string
	revision  string
	goversion string
	builddate string
	builduser string
)

const LoopMin = 60

func init() {
	formatter := new(logrus.JSONFormatter)
	formatter.TimestampFormat = "2006-01-02 15:04:05"
	logrus.SetFormatter(formatter)
	callerLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}
	stackLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}
	logrus.AddHook(logrus_stack.NewHook(callerLevels, stackLevels))

	if os.Getenv("DEBUG") == "" {
		logrus.SetLevel(logrus.InfoLevel)
	} else {
		logrus.SetLevel(logrus.DebugLevel)
	}
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
	defer util.RemovePidFile()

	hostname, err := os.Hostname()
	if err != nil {
		logrus.Fatal(err)
	}

	wd := c.GlobalString("workdir")
	err = util.CreateWorkDir(wd)
	if err != nil {
		logrus.Fatal(err)
	}

	server, err := scan.DetectOS()
	if err != nil {
		logrus.Fatal(err)
	}

	client := veeta.NewClient(conf.ServerEndpoint, conf.Token)

	for {
		logrus.Info("Start to acquire package information")
		err = server.EnsureInstallPackages()
		if err != nil {
			logrus.Fatal(err)
		}

		id, err := ioutil.ReadFile(path.Join(wd, ".id"))
		if err != nil {
			logrus.Info(err)
		}

		h := veeta.Host{
			HostID: string(id),
			Name:   hostname,
			Service: veeta.Service{
				Name: conf.Service,
			},
			ScanResult: *server.GetScanResult(),
		}
		h.ScanResult.ScannedAt = time.Now()

		if len(id) == 0 {
			logrus.Info("Register new host")
			if err := client.CreateHost(&h); err != nil {
				logrus.Error(err, " http request error")
			} else {
				if err := util.WriteID(path.Join(wd, ".id"), h.HostID); err != nil {
					logrus.Fatal(err, " can't write host id")
				}
			}
		} else {
			logrus.Info("Update host information")
			if err := client.UpdateHost(&h); err != nil {
				logrus.Error(err, " http request error")
			}
		}

		if err := server.AddSecurityPackageAlert(&h.Alerts); err != nil {
			logrus.Error(err, " add security package")
		}

		logrus.Infof("Register %v alert", len(h.Alerts))

		if len(h.Alerts) > 0 {
			for i, a := range h.Alerts {
				fixCVEs, err := server.GetFixCVEIDs(scan.Package{
					Name:    a.PackageName,
					Version: a.Version,
				})
				if err != nil {
					logrus.Error(err, " fetch changelog error")
					continue
				}
				cves := scan.FilterResolvCVEs(a.CVEs, fixCVEs)
				h.Alerts[i].CVEs = cves
			}
			// register alert
			logrus.Info("Update host information with Alert")
			if err := client.UpdateHost(&h); err != nil {
				logrus.Error(err, " http request error")
			}
		}
		time.Sleep(LoopMin * time.Minute)
	}
}
