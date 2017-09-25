package scan

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	cache "github.com/patrickmn/go-cache"
	"github.com/pyama86/vaz/config"
	"github.com/sirupsen/logrus"
)

type debian struct {
	ScanResult
	cache *cache.Cache
}

type packCandidateVer struct {
	Name      string
	Installed string
	Candidate string
}

func newDebian() *debian {
	return &debian{
		cache: cache.New(CacheLifeTime*time.Minute, CachePurgeTime*time.Minute),
	}
}
func (o *debian) rebootRequired() (bool, error) {
	r := exec("test -f /var/run/reboot-required")
	switch r.ExitStatus {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("Failed to check reboot reauired: %s", r)
	}
}

func (o *debian) EnsureInstallPackages() error {
	release, version, err := o.runningKernel()
	if err != nil {
		logrus.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	rebootRequired, err := o.rebootRequired()
	if err != nil {
		logrus.Errorf("Failed to detect the kernel reboot required: %s", err)
		return err
	}
	o.Kernel = Kernel{
		Version:        version,
		Release:        release,
		RebootRequired: rebootRequired,
	}

	installed, updatable := Packages{}, Packages{}
	r := exec("dpkg-query -W")
	if !r.isSuccess() {
		return errors.New(r.Stderr)
	}
	//  e.g.
	//  curl	7.19.7-40.el6_6.4
	//  openldap	2.4.39-8.el6
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); len(trimmed) != 0 {
			name, version, err := o.parseScannedPackagesLine(trimmed)
			if err != nil {
				return fmt.Errorf("Debian: Failed to parse package line: %s", line)
			}
			installed[name] = Package{
				Name:    name,
				Version: version,
			}
		}
	}

	updatableNames, err := o.getUpdatablePackNames()
	if err != nil {
		return err
	}
	for _, name := range updatableNames {
		for _, pack := range installed {
			if pack.Name == name {
				updatable[name] = pack
				break
			}
		}
	}

	// Fill the candidate versions of upgradable packages
	err = o.fillCandidateVersion(updatable)
	if err != nil {
		return fmt.Errorf("Failed to fill candidate versions. err: %s", err)
	}
	installed.MergeNewVersion(updatable)
	o.Packages = installed
	return nil
}

func (o *debian) fillCandidateVersion(updatables Packages) (err error) {
	names := []string{}
	for name := range updatables {
		names = append(names, name)
	}
	cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 apt-cache policy %s", strings.Join(names, " "))
	r := exec(cmd)
	if !r.isSuccess() {
		return errors.New(r.Stderr)
	}
	packChangelog := o.splitAptCachePolicy(r.Stdout)
	for k, v := range packChangelog {
		ver, err := o.parseAptCachePolicy(v, k)
		if err != nil {
			return fmt.Errorf("Failed to parse %s", err)
		}
		pack, ok := updatables[k]
		if !ok {
			return fmt.Errorf("Not found: %s", k)
		}
		pack.NewVersion = ver.Candidate
		updatables[k] = pack
	}
	return
}

func (o *debian) parseAptCachePolicy(stdout, name string) (packCandidateVer, error) {
	ver := packCandidateVer{Name: name}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "Installed:":
			ver.Installed = fields[1]
		case "Candidate:":
			ver.Candidate = fields[1]
			return ver, nil
		default:
			// nop
		}
	}
	return ver, fmt.Errorf("Unknown Format: %s", stdout)
}

func (o *debian) splitAptCachePolicy(stdout string) map[string]string {
	re := regexp.MustCompile(`(?m:^[^ \t]+:\r?\n)`)
	ii := re.FindAllStringIndex(stdout, -1)
	ri := []int{}
	for i := len(ii) - 1; 0 <= i; i-- {
		ri = append(ri, ii[i][0])
	}
	splitted := []string{}
	lasti := len(stdout)
	for _, i := range ri {
		splitted = append(splitted, stdout[i:lasti])
		lasti = i
	}

	packChangelog := map[string]string{}
	for _, r := range splitted {
		packName := r[:strings.Index(r, ":")]
		packChangelog[packName] = r
	}
	return packChangelog
}

func (o *debian) getUpdatablePackNames() (packNames []string, err error) {
	cmd := "LANGUAGE=en_US.UTF-8 apt-get dist-upgrade --dry-run"
	r := exec(cmd)
	if r.isSuccess(0, 1) {
		return o.parseAptGetUpgrade(r.Stdout)
	}
	return packNames, fmt.Errorf(
		"Failed to %s. status: %d, stdout: %s, stderr: %s",
		cmd, r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *debian) parseAptGetUpgrade(stdout string) (updatableNames []string, err error) {
	startRe := regexp.MustCompile(`The following packages will be upgraded:`)
	stopRe := regexp.MustCompile(`^(\d+) upgraded.*`)
	startLineFound, stopLineFound := false, false

	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if !startLineFound {
			if matche := startRe.MatchString(line); matche {
				startLineFound = true
			}
			continue
		}
		result := stopRe.FindStringSubmatch(line)
		if len(result) == 2 {
			nUpdatable, err := strconv.Atoi(result[1])
			if err != nil {
				return nil, fmt.Errorf(
					"Failed to scan upgradable packages number. line: %s", line)
			}
			if nUpdatable != len(updatableNames) {
				return nil, fmt.Errorf(
					"Failed to scan upgradable packages, expected: %s, detected: %d",
					result[1], len(updatableNames))
			}
			stopLineFound = true
			break
		}
		updatableNames = append(updatableNames, strings.Fields(line)...)
	}
	if !startLineFound {
		// no upgrades
		return
	}
	if !stopLineFound {
		// There are upgrades, but not found the stop line.
		return nil, fmt.Errorf("Failed to scan upgradable packages")
	}
	return
}

var packageLinePattern = regexp.MustCompile(`^([^\t']+)\t(.+)$`)

func (o *debian) parseScannedPackagesLine(line string) (name, version string, err error) {
	result := packageLinePattern.FindStringSubmatch(line)
	if len(result) == 3 {
		// remove :amd64, i386...
		name = result[1]
		if i := strings.IndexRune(name, ':'); i >= 0 {
			name = name[:i]
		}
		version = result[2]
		return
	}

	return "", "", fmt.Errorf("Unknown format: %s", line)
}

func trim(str string) string {
	return strings.TrimSpace(str)
}

// Ubuntu, Debian, Raspbian
// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/debian.rb
func detectDebian() (itsMe bool, deb osTypeInterface, err error) {
	deb = newDebian()

	if r := exec("ls /etc/debian_version"); !r.isSuccess() {
		if r.Error != nil {
			return false, deb, nil
		}
		if r.ExitStatus == 255 {
			return false, deb, fmt.Errorf(r.Stderr)
		}
		logrus.Debugf("Not Debian like Linux. %s", r)
		return false, deb, nil
	}

	// Raspbian
	// lsb_release in Raspbian Jessie returns 'Distributor ID: Raspbian'.
	// However, lsb_release in Raspbian Wheezy returns 'Distributor ID: Debian'.
	if r := exec("cat /etc/issue"); r.isSuccess() {
		//  e.g.
		//  Raspbian GNU/Linux 7 \n \l
		result := strings.Fields(r.Stdout)
		if len(result) > 2 && result[0] == config.Raspbian {
			distro := strings.ToLower(trim(result[0]))
			deb.setDistro(distro, trim(result[2]))
			return true, deb, nil
		}
	}

	if r := exec("lsb_release -ir"); r.isSuccess() {
		//  e.g.
		//  root@fa3ec524be43:/# lsb_release -ir
		//  Distributor ID:	Ubuntu
		//  Release:	14.04
		re := regexp.MustCompile(`(?s)^Distributor ID:\s*(.+?)\n*Release:\s*(.+?)$`)
		result := re.FindStringSubmatch(trim(r.Stdout))

		if len(result) == 0 {
			deb.setDistro("debian/ubuntu", "unknown")
			logrus.Warnf(
				"Unknown Debian/Ubuntu version. lsb_release -ir: %s", r)
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistro(distro, trim(result[2]))
		}
		return true, deb, nil
	}

	if r := exec("cat /etc/lsb-release"); r.isSuccess() {
		//  e.g.
		//  DISTRIB_ID=Ubuntu
		//  DISTRIB_RELEASE=14.04
		//  DISTRIB_CODENAME=trusty
		//  DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
		re := regexp.MustCompile(`(?s)^DISTRIB_ID=(.+?)\n*DISTRIB_RELEASE=(.+?)\n.*$`)
		result := re.FindStringSubmatch(trim(r.Stdout))
		if len(result) == 0 {
			logrus.Warnf(
				"Unknown Debian/Ubuntu. cat /etc/lsb-release: %s", r)
			deb.setDistro("debian/ubuntu", "unknown")
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistro(distro, trim(result[2]))
		}
		return true, deb, nil
	}

	// Debian
	cmd := "cat /etc/debian_version"
	if r := exec(cmd); r.isSuccess() {
		deb.setDistro(config.Debian, trim(r.Stdout))
		return true, deb, nil
	}

	return false, deb, nil
}

func (o *debian) GetFixCVEIDs(pack Package) ([]string, error) {
	var changelog string
	var err error
	key := getMD5Hash(pack.Name + pack.Version)
	logrus.Infof("Acquisition of change log started %s", pack.Name)
	if x, found := o.cache.Get(key); found {
		changelog = x.(string)
	} else {
		cmd := ""
		switch o.Family {
		case config.Ubuntu, config.Raspbian:
			cmd = fmt.Sprintf(`PAGER=cat apt-get -q=2 changelog %s`, pack.Name)
		case config.Debian:
			cmd = fmt.Sprintf(`PAGER=cat aptitude -q=2 changelog %s`, pack.Name)
		}
		changelog, err = o.getChangeLog(cmd)
		if err != nil {
			return nil, err
		}
		o.cache.Set(key, changelog, cache.DefaultExpiration)
	}
	cveIDs := o.getFixCVEIDsFromChangelog(o.ChangeLogStartPattern(pack), changelog)
	return cveIDs, nil
}

func (o *debian) ChangeLogStartPattern(pack Package) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`^%s\s+\(%s\)`, regexp.QuoteMeta(pack.Name), regexp.QuoteMeta(pack.Version)))
}
