TEST ?= $(shell go list ./... | grep -v vendor)
VERSION = $(shell cat version)
REVISION = $(shell git describe --always)

INFO_COLOR=\033[1;34m
RESET=\033[0m
BOLD=\033[1m

DIST ?= unknown
SOURCES=COPYING pkg/linux_amd64/vaz vaz.conf.example

default: build
ci: depsdev test vet lint

dev:
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Run Development Container$(RESET)"
	misc/dev

deps: ## Install dependencies
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Installing Dependencies$(RESET)"
	go get -u github.com/golang/dep/...
	dep ensure

depsdev: deps ## Installing dependencies for development
	go get github.com/golang/lint/golint
	go get -u github.com/tcnksm/ghr
	go get github.com/mitchellh/gox

test: ## Run test
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Testing$(RESET)"
	go test -v $(TEST) -timeout=30s -parallel=4
	go test -race $(TEST)

vet: ## Exec go vet
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Vetting$(RESET)"
	go vet $(TEST)

lint: ## Exec golint
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Linting$(RESET)"
	golint -min_confidence 1.1 -set_exit_status $(TEST)

build: depsdev  ## Build as linux binary
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Building$(RESET)"
	./misc/build $(VERSION) $(REVISION)

ghr: ## Upload to Github releases without token check
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Releasing for Github$(RESET)"
	ghr -u pyama86 v$(VERSION)-$(REVISION) pkg

dist: build ## Upload to Github releases
	@test -z $(GITHUB_TOKEN) || test -z $(GITHUB_API) || $(MAKE) ghr

rpm:
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Packaging for RPM$(RESET)"
	rm -rf /root/rpmbuild
	mkdir -p /root/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp $(SOURCES) /root/rpmbuild/SOURCES
	cp  rpm/files/* /root/rpmbuild/SOURCES
	echo '%_signature gpg' >> ~/.rpmmacros
	echo '%_gpg_name vaz-server' >> ~/.rpmmacros
	rpmbuild -ba rpm/vaz.spec
	cp /root/rpmbuild/RPMS/*/*.rpm /vaz/builds

deb:
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Packaging for RPM$(RESET)"
	rm -rf  /root/deb/debian
	mkdir -p /root/deb/debian
	cp $(SOURCES) /root/deb/debian/
	mv /root/deb/debian/vaz /root/deb/debian/vaz.bin
	cp deb/* /root/deb/debian/
	cd /root/deb && yes | debuild -uc -us && cp ../*.deb /vaz/builds/

rpm-repo:
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Create Repo for RPM$(RESET)"
	gpg --import keys/public.key;gpg --import --allow-secret-key-import keys/private.key && \
	echo '%_signature gpg' >> ~/.rpmmacros && \
	echo '%_gpg_name vaz-server' >> ~/.rpmmacros
	install -d -m 755 releases/centos/x86_64
	cp -pr builds/*.rpm releases/centos/x86_64/ && \
	rpm --addsign releases/centos/x86_64/*.rpm && \
	createrepo --checksum sha releases/centos/x86_64/
deb-repo:
	@echo "$(INFO_COLOR)==> $(RESET)$(BOLD)Create Repo for DEB$(RESET)"
	gpg --import keys/public.key;gpg --import --allow-secret-key-import keys/private.key && \
	mkdir -p releases/debian && \
	cp builds/*.deb releases/debian && \
	cp -pr debrepo/conf releases/debian && \
	cd releases/debian && \
	reprepro includedeb vaz *.deb

pkg: ## Create some distribution packages
	rm -rf builds && mkdir builds
	docker-compose up deb16
	docker-compose up rpm6 rpm7

repo:
	rm -rf releases/debian/{db, main}
	docker-compose run rpm-repo
	docker-compose run deb-repo

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(INFO_COLOR)%-30s$(RESET) %s\n", $$1, $$2}'

.PHONY: help dist distclean deps depsdev test testdev rpm deb rpm-repo deb-repo dev pkg repo
