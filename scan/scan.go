package scan

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pyama86/vaz/config"
	"github.com/sirupsen/logrus"
)

const CacheLifeTime = 600
const CachePurgeTime = 610

type ScanResult struct {
	ScannedAt time.Time
	Family    string
	Release   string
	Packages  Packages
	Kernel    Kernel
}

type Kernel struct {
	Release        string
	Version        string
	RebootRequired bool
}

type Alert struct {
	CVEs        []string
	PackageName string
	Version     string
}
type Alerts []Alert

func (l *ScanResult) setDistro(fam, rel string) {
	l.Family = fam
	l.Release = rel
}

func (l *ScanResult) GetPackages() *Packages {
	return &l.Packages
}

func (l *ScanResult) GetScanResult() *ScanResult {
	return l
}

type Package struct {
	Name       string
	Version    string
	Release    string
	NewVersion string
	NewRelease string
	Arch       string
}

type Packages map[string]Package

type osTypeInterface interface {
	setDistro(string, string)
	EnsureInstallPackages() error
	GetPackages() *Packages
	GetScanResult() *ScanResult
	GetFixCVEIDs(Package) ([]string, error)
}

func DetectOS() (osType osTypeInterface, err error) {
	var itsMe bool
	var fatalErr error
	itsMe, osType, fatalErr = detectDebian()
	if fatalErr != nil {
		return nil, fatalErr
	}

	if itsMe {
		return
	}

	if itsMe, osType = detectRedhat(); itsMe {
		return
	}

	if itsMe {
		return
	}

	logrus.Fatal("unsupport OS")
	return
}

func (ps Packages) MergeNewVersion(as Packages) {
	for _, a := range as {
		if pack, ok := ps[a.Name]; ok {
			pack.NewVersion = a.NewVersion
			pack.NewRelease = a.NewRelease
			ps[a.Name] = pack
		}
	}
}

func appendIfMissing(slice []string, s string) []string {
	for _, ele := range slice {
		if ele == s {
			return slice
		}
	}
	return append(slice, s)
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func FilterResolvCVEs(cves1 []string, fixCVEs []string) []string {
	var diff []string

	for _, s1 := range cves1 {
		found := false
		for _, s2 := range fixCVEs {
			if s1 == s2 {
				found = true
				break
			}
		}
		// String not found. We add it to return slice
		if !found {
			diff = append(diff, s1)
		}
	}

	return diff
}

func (l *ScanResult) runningKernel() (release, version string, err error) {
	r := exec("uname -r")
	if !r.isSuccess() {
		return "", "", errors.New(r.Stderr)
	}
	release = strings.TrimSpace(r.Stdout)

	switch l.Family {
	case config.Debian:
		r := exec("uname -a")
		if !r.isSuccess() {
			return "", "", errors.New(r.Stderr)
		}
		ss := strings.Fields(r.Stdout)
		if 6 < len(ss) {
			version = ss[6]
		}
	}
	return
}

// MajorVersion returns Major version
func (l *ScanResult) MajorVersion() (ver int, err error) {
	if 0 < len(l.Release) {
		ver, err = strconv.Atoi(strings.Split(l.Release, ".")[0])
	} else {
		err = errors.New("Release is empty")
	}
	return
}

func (o *ScanResult) getChangeLog(cmd string) (string, error) {
	r := exec(cmd)
	if !r.isSuccess() {
		return "", errors.New(r.Stderr)
	}

	stdout := strings.Replace(r.Stdout, "\r", "", -1)
	return stdout, nil
}

func (o *ScanResult) getFixCVEIDsFromChangelog(startRe *regexp.Regexp, changelog string) []string {
	startLineFound := false
	cveIDs := []string{}
	var cveRe = regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)

	lines := strings.Split(changelog, "\n")
	for _, line := range lines {
		if !startLineFound {
			if matche := startRe.MatchString(line); matche {
				startLineFound = true
			}
			continue
		}

		if startLineFound {
			if matches := cveRe.FindAllString(line, -1); 0 < len(matches) {
				for _, m := range matches {
					cveIDs = appendIfMissing(cveIDs, m)
				}
			}
		}
	}
	return cveIDs
}
