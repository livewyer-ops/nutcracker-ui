TARGET  ?= build

GO_VERSION ?= 1.6
DOCKER ?= docker
DOCKERTAG ?= latest
DOCKERREPO ?= localhost
APPNAME = nutcracker-ui
APPPATH = github.com/nutmegdevelopment
WORKDIR ?= $(CURDIR)


build:
	$(DOCKER) run --rm \
		--privileged \
		-v $(WORKDIR):/src \
		-v /var/run/docker.sock:/var/run/docker.sock \
		centurylink/golang-builder \
		$(DOCKERREPO)/$(APPNAME):$(DOCKERTAG)
	$(DOCKER) tag -f $(DOCKERREPO)/$(APPNAME):$(DOCKERTAG) $(DOCKERREPO)/$(APPNAME):latest

push:
	$(DOCKER) push $(DOCKERREPO)/$(APPNAME):$(DOCKERTAG)
	$(DOCKER) push $(DOCKERREPO)/$(APPNAME):latest

clean:
	rm -f $(APPNAME)
