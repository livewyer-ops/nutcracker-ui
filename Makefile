TARGET  ?= install

GO_VERSION ?= 1.6
DOCKER ?= docker

install:
	$(DOCKER) run -v $(CURDIR)\:/go/bin -e CGO_ENABLED=0 --rm golang\:$(GO_VERSION) go get -v github.com/nutmegdevelopment/nutcracker-ui
	$(DOCKER) build .
	rm -f nutcracker-ui

test:
	$(DOCKER) run -v $(CURDIR)\:/go/bin -e CGO_ENABLED=0 --rm golang\:$(GO_VERSION) go get github.com/nutmegdevelopment/nutcracker-ui && go test github.com/nutmegdevelopment/nutcracker-ui

clean:
	nutcracker-ui
