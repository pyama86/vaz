# vaz
[![Build Status](https://travis-ci.org/pyama86/vaz.svg?branch=master)](https://travis-ci.org/pyama86/vaz)

vaz is [veeta](https://www.veeta.tech) server client.
Send package information to veeta to determine if there is vulnerability

<p align="center">
 <img alt="VEETA" src="https://github.com/pyama86/vaz/blob/master/img/veeta.png?raw=true" style="width: 75%">
</p>

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

# special thanks
The base of vaz is [vuls](https://github.com/future-architect/vuls). vuls is a very wonderful product.

## author
* pyama86
