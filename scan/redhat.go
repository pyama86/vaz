package scan

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/pyama86/vaz/config"

	"github.com/sirupsen/logrus"
)

type redhat struct {
	ScanResult
	cache *cache.Cache
}

func newRedhat() *redhat {
	return &redhat{
		cache: cache.New(CacheLifeTime*time.Minute, CachePurgeTime*time.Minute),
	}
}
func (o *redhat) rebootRequired() (bool, error) {
	r := exec("rpm -q --last kernel | head -n1")
	if !r.isSuccess() {
		return false, fmt.Errorf("Failed to detect the last installed kernel : %v", r)
	}
	lastInstalledKernelVer := strings.Fields(r.Stdout)[0]
	running := fmt.Sprintf("kernel-%s", o.Kernel.Release)
	return running != lastInstalledKernelVer, nil
}

func (o *redhat) EnsureInstallPackages() error {
	installed, err := o.scanInstalledPackages()
	if err != nil {
		logrus.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	rebootRequired, err := o.rebootRequired()
	if err != nil {
		logrus.Errorf("Failed to detect the kernel reboot required: %s", err)
		return err
	}
	o.Kernel.RebootRequired = rebootRequired

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		logrus.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	installed.MergeNewVersion(updatable)
	o.Packages = installed
	return nil
}

func (o *redhat) scanInstalledPackages() (Packages, error) {
	release, version, err := o.runningKernel()
	if err != nil {
		return nil, err
	}
	o.Kernel = Kernel{
		Release: release,
		Version: version,
	}

	installed := Packages{}
	var cmd string
	majorVersion, _ := o.MajorVersion()
	if majorVersion < 6 {
		cmd = "rpm -qa --queryformat '%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH}\n'"
	} else {
		cmd = "rpm -qa --queryformat '%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH}\n'"
	}
	r := exec(cmd)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Scan packages failed: %v", r)
	}

	// openssl 0 1.0.1e	30.el6.11 x86_64
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		if trimed := strings.TrimSpace(line); len(trimed) != 0 {
			pack, err := o.parseInstalledPackagesLine(line)
			if err != nil {
				return nil, err
			}

			// Kernel package may be isntalled multiple versions.
			// From the viewpoint of vulnerability detection,
			// pay attention only to the running kernel
			if pack.Name == "kernel" {
				ver := fmt.Sprintf("%s-%s.%s", pack.Version, pack.Release, pack.Arch)
				if o.Kernel.Release != ver {
					logrus.Debugf("Not a running kernel: %s, uname: %s", ver, release)
					continue
				} else {
					logrus.Debugf("Running kernel: %s, uname: %s", ver, release)
				}
			}
			installed[pack.Name] = pack
		}
	}
	return installed, nil
}

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat() (itsMe bool, red osTypeInterface) {
	red = newRedhat()

	if r := exec("ls /etc/fedora-release"); r.isSuccess() {
		red.setDistro(config.Fedora, "unknown")
		logrus.Warn("Fedora not tested yet: %s", r)
		return true, red
	}

	if r := exec("ls /etc/oracle-release"); r.isSuccess() {
		// Need to discover Oracle Linux first, because it provides an
		// /etc/redhat-release that matches the upstream distribution
		if r := exec("cat /etc/oracle-release"); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				logrus.Warn("Failed to parse Oracle Linux version: %s", r)
				return true, red
			}

			release := result[2]
			red.setDistro(config.Oracle, release)
			return true, red
		}
	}

	if r := exec("ls /etc/redhat-release"); r.isSuccess() {
		// https://www.rackaid.com/blog/how-to-determine-centos-or-red-hat-version/
		// e.g.
		// $ cat /etc/redhat-release
		// CentOS release 6.5 (Final)
		if r := exec("cat /etc/redhat-release"); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				logrus.Warn("Failed to parse RedHat/CentOS version: %s", r)
				return true, red
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				red.setDistro(config.CentOS, release)
			default:
				red.setDistro(config.RedHat, release)
			}
			return true, red
		}
		return true, red
	}

	if r := exec("ls /etc/system-release"); r.isSuccess() {
		family := config.Amazon
		release := "unknown"
		if r := exec("cat /etc/system-release"); r.isSuccess() {
			fields := strings.Fields(r.Stdout)
			if len(fields) == 5 {
				release = fields[4]
			}
		}
		red.setDistro(family, release)
		return true, red
	}

	return false, red
}

func (o *redhat) parseInstalledPackagesLine(line string) (Package, error) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return Package{},
			fmt.Errorf("Failed to parse package line: %s", line)
	}
	ver := ""
	//epoch := fields[1]
	//if epoch == "0" || epoch == "(none)" {
	ver = fields[2]
	//	} else {
	//		ver = fmt.Sprintf("%s:%s", epoch, fields[2])
	//	}

	return Package{
		Name:    fields[0],
		Version: ver,
		Release: fields[3],
		Arch:    fields[4],
	}, nil
}

func (o *redhat) scanUpdatablePackages() (Packages, error) {
	cmd := "repoquery --all --pkgnarrow=updates --qf='%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{REPO}'"

	r := exec(cmd)
	if !r.isSuccess() {
		return nil, fmt.Errorf(r.Stderr)
	}

	// Collect Updateble packages, installed, candidate version and repository.
	return o.parseUpdatablePacksLines(r.Stdout)
}

// parseUpdatablePacksLines parse the stdout of repoquery to get package name, candidate version
func (o *redhat) parseUpdatablePacksLines(stdout string) (Packages, error) {
	updatable := Packages{}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}
		pack, err := o.parseUpdatablePacksLine(line)
		if err != nil {
			return updatable, err
		}
		updatable[pack.Name] = pack
	}
	return updatable, nil
}

func (o *redhat) parseUpdatablePacksLine(line string) (Package, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return Package{}, fmt.Errorf("Unknown format: %s, fields: %s", line, fields)
	}

	ver := ""
	epoch := fields[1]
	if epoch == "0" {
		ver = fields[2]
	} else {
		ver = fmt.Sprintf("%s:%s", epoch, fields[2])
	}

	p := Package{
		Name:       fields[0],
		NewVersion: ver,
		NewRelease: fields[3],
	}
	return p, nil
}

func (o *redhat) GetFixCVEIDs(pack Package) ([]string, error) {
	var changelog string
	var err error
	key := getMD5Hash(pack.Name + pack.Version)
	logrus.Infof("Acquisition of change log started %s", pack.Name)
	if x, found := o.cache.Get(key); found {
		changelog = x.(string)
	} else {
		changelog, err = o.getChangeLog(fmt.Sprintf("rpm -q --changelog %s", pack.Name))
		if err != nil {
			return nil, err
		}
		o.cache.Set(key, changelog, cache.DefaultExpiration)
	}
	cveIDs := o.getFixCVEIDsFromChangelog(o.ChangeLogStartPattern(pack), changelog)
	return cveIDs, nil
}

func (o *redhat) ChangeLogStartPattern(pack Package) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`^\*.+%s`, regexp.QuoteMeta(pack.Version)))
}
