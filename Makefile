PROJECT_PATH = github.com/pantheon-systems/go-certauth


.PHONY: all
all: test build


.PHONY: test
test:
	go test $(PROJECT_PATH)
	go test $(PROJECT_PATH)/pantheon


.PHONY: build
build:
	go build $(PROJECT_PATH)
	go build $(PROJECT_PATH)/pantheon
