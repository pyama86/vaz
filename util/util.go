package util

import (
	"io/ioutil"
	"os"

	"github.com/facebookgo/pidfile"
	"github.com/sirupsen/logrus"
)

func existsPath(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func RemovePidFile() {
	if err := os.Remove(pidfile.GetPidfilePath()); err != nil {
		logrus.Fatalf("Error removing %s: %s", pidfile.GetPidfilePath(), err)
	}
}

func WriteID(path string, id string) error {
	return ioutil.WriteFile(path, []byte(id), os.ModePerm)
}

func CreateWorkDir(path string) error {
	found, err := existsPath(path)
	if err != nil {
		return err
	}

	if !found {
		if err := os.Mkdir(path, 0777); err != nil {
			return err
		}
	}
	return nil
}
