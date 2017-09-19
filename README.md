# vaz
<p align="center">
  <img alt="VEETA" src="https://github.com/pyama86/vaz/blob/master/img/veeta.png?raw=true">
</p>

[![Build Status](https://travis-ci.org/pyama86/vaz.svg?branch=master)](https://travis-ci.org/pyama86/vaz)

vaz is [veeta](https://veeta.org) server client.
Send package information to veeta to determine if there is vulnerability

# install

- rhel/centos

```
$ curl -fsSL https://repo.veeta.org/scripts/yum-repo.sh | sh
$ yum install vaz
$ mv /etc/vaz.conf.sample /etc/vaz.conf
$ vi /etc/vaz.conf
$ service vaz start
```

- debian/ubuntu

```
$ curl -fsSL https://repo.veeta.org/scripts/apt-repo.sh | sh
$ apt-get install vaz
$ mv /etc/vaz.conf.sample /etc/vaz.conf
$ vi /etc/vaz.conf
$ service vaz start
```

# configure
- /etc/vaz.conf

```
service = "your service name"
# Please create with veeta.org
token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## author
* pyama86
