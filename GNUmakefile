SHELL := /bin/bash

PWD                                    ?= pwd_unknown

THIS_FILE                              := $(lastword $(MAKEFILE_LIST))
export THIS_FILE
TIME                                   := $(shell date +%s)
export TIME

ARCH                                   :=$(shell uname -m)
export ARCH
ifeq ($(ARCH),x86_64)
TRIPLET                                :=x86_64-linux-gnu
export TRIPLET
endif
ifeq ($(ARCH),arm64)
TRIPLET                                :=aarch64-linux-gnu
export TRIPLET
endif
ifeq ($(services),)
services                               :=bitcoind,lnd,cln,rtl,thunderhub,docs
else
services                               :=$(services)
endif
export services
ifeq ($(user),)
HOST_USER                              := root
HOST_UID                               := $(strip $(if $(uid),$(uid),0))
else
HOST_USER                              :=  $(strip $(if $(USER),$(USER),nodummy))
HOST_UID                               :=  $(strip $(if $(shell id -u),$(shell id -u),4000))
endif
export HOST_USER
export HOST_UID

ifeq ($(target),)
SERVICE_TARGET                         ?= shell
else
SERVICE_TARGET                         := $(target)
endif
export SERVICE_TARGET

ifeq ($(docker),)
DOCKER                                 := $(shell which docker)
else
DOCKER                                 := $(docker)
endif
export DOCKER

ifeq ($(compose),)
DOCKER_COMPOSE                         := $(shell which docker-compose)
else
DOCKER_COMPOSE                         := $(compose)
endif
export DOCKER_COMPOSE
ifeq ($(reset),true)
RESET:=true
else
RESET:=false
endif
export RESET

PYTHON                                 := $(shell which python)
export PYTHON
PYTHON2                                := $(shell which python2)
export PYTHON2
PYTHON3                                := $(shell which python3)
export PYTHON3

PIP                                    := $(shell which pip)
export PIP
PIP2                                   := $(shell which pip2)
export PIP2
PIP3                                   := $(shell which pip3)
export PIP3

python_version_full := $(wordlist 2,4,$(subst ., ,$(shell python3 --version 2>&1)))
python_version_major := $(word 1,${python_version_full})
python_version_minor := $(word 2,${python_version_full})
python_version_patch := $(word 3,${python_version_full})

my_cmd.python.3 := $(PYTHON3) some_script.py3
my_cmd := ${my_cmd.python.${python_version_major}}

PYTHON_VERSION                         := ${python_version_major}.${python_version_minor}.${python_version_patch}
PYTHON_VERSION_MAJOR                   := ${python_version_major}
PYTHON_VERSION_MINOR                   := ${python_version_minor}

export python_version_major
export python_version_minor
export python_version_patch
export PYTHON_VERSION

#PROJECT_NAME defaults to name of the current directory.
ifeq ($(project),)
PROJECT_NAME                           := $(notdir $(PWD))
else
PROJECT_NAME                           := $(project)
endif
export PROJECT_NAME

#GIT CONFIG
GIT_USER_NAME                          := $(shell git config user.name)
export GIT_USER_NAME
GIT_USER_EMAIL                         := $(shell git config user.email)
export GIT_USER_EMAIL
GIT_SERVER                             := https://github.com
export GIT_SERVER

GIT_REPO_NAME                          := $(PROJECT_NAME)
export GIT_REPO_NAME

#Usage
#make package-all profile=rsafier
#make package-all profile=asherp
#note on GH_TOKEN.txt file below
ifeq ($(profile),)
GIT_PROFILE                            := $(GIT_USER_NAME)
ifeq ($(GIT_REPO_ORIGIN),git@github.com:PLEBNET_PLAYGROUND/plebnet-playground-docker.dev.git)
GIT_PROFILE                            := PLEBNET-PLAYGROUND
endif
ifeq ($(GIT_REPO_ORIGIN),https://github.com/PLEBNET_PLAYGROUND/plebnet-playground-docker.dev.git)
GIT_PROFILE                            := PLEBNET-PLAYGROUND
endif
else
GIT_PROFILE                            := $(profile)
endif
export GIT_PROFILE

GIT_BRANCH                             := $(shell git rev-parse --abbrev-ref HEAD)
export GIT_BRANCH
GIT_HASH                               := $(shell git rev-parse --short HEAD)
export GIT_HASH
GIT_PREVIOUS_HASH                      := $(shell git rev-parse --short HEAD^1)
export GIT_PREVIOUS_HASH
GIT_REPO_ORIGIN                        := $(shell git remote get-url origin)
export GIT_REPO_ORIGIN
GIT_REPO_PATH                          := $(HOME)/$(GIT_REPO_NAME)
export GIT_REPO_PATH

ifneq ($(bitcoin-datadir),)
BITCOIN_DATA_DIR                       := $(bitcoin-datadir)
else
BITCOIN_DATA_DIR                       := $(HOME)/.bitcoin
endif
export BITCOIN_DATA_DIR

ifeq ($(nocache),true)
NOCACHE                                := --no-cache
#Force parallel build when --no-cache to speed up build
PARALLEL                               := --parallel
else
NOCACHE                                :=
PARALLEL                               :=
endif
ifeq ($(parallel),true)
PARALLEL                               := --parallel
endif
ifeq ($(para),true)
PARALLEL                               := --parallel
endif
export NOCACHE
export PARALLEL

ifeq ($(verbose),true)
VERBOSE                                := --verbose
else
VERBOSE                                :=
endif
export VERBOSE

ifeq ($(port),)
PUBLIC_PORT                            := 80
else
PUBLIC_PORT                            := $(port)
endif
export PUBLIC_PORT

ifeq ($(nodeport),)
NODE_PORT                              := 8333
else
NODE_PORT                              := $(nodeport)
endif
export NODE_PORT

ifneq ($(passwd),)
PASSWORD                               := $(passwd)
else
PASSWORD                               := changeme
endif
export PASSWORD

ifeq ($(cmd),)
CMD_ARGUMENTS                          :=
else
CMD_ARGUMENTS                          := $(cmd)
endif
export CMD_ARGUMENTS

PACKAGE_PREFIX                         := ghcr.io
export PACKAGE_PREFIX
.PHONY: - all
-:
#NOTE: 2 hashes are detected as 1st column output with color
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?##/ {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: help
help:## 	print verbose help
	@echo 'make [COMMAND]	[EXTRA_ARGUMENTS]	[INFO]'
	@echo ''
	@echo 'make help                       print help'
	@echo 'make report                     print environment variables'
	@echo '                                nocache=true verbose=true'
	@echo ''
	@echo '[DEV ENVIRONMENT]:	'
	@echo ''
	@echo 'make signin profile=gh-user     ~/GH_TOKEN.txt required from github.com'
	@echo 'make build'
	@echo 'make package-all'
	@echo ''
	@echo '[EXAMPLES]:'
	@echo ''
	@echo 'make run nocache=true verbose=true'
	@echo ''
	@echo 'make init && play help'
	@echo ''
	@sed -n 's/^# //p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/# /'
	@sed -n 's/^## //p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/## /'
	@sed -n 's/^### //p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/### /'

.PHONY: report
report:## 	print environment arguments
	@echo ''
	@echo '	[ARGUMENTS]	'
	@echo '      args:'
	@echo '        - THIS_FILE=${THIS_FILE}'
	@echo '        - TIME=${TIME}'
	@echo '        - ARCH=${ARCH}'
	@echo '        - TRIPLET=${TRIPLET}'
	@echo '        - PROJECT_NAME=${PROJECT_NAME}'
	@echo '        - HOME=${HOME}'
	@echo '        - PWD=${PWD}'
	@echo '        - PYTHON=${PYTHON}'
	@echo '        - PYTHON3=${PYTHON3}'
	@echo '        - PYTHON_VERSION=${PYTHON_VERSION}'
	@echo '        - PYTHON_VERSION_MAJOR=${PYTHON_VERSION_MAJOR}'
	@echo '        - PYTHON_VERSION_MINOR=${PYTHON_VERSION_MINOR}'
	@echo '        - PIP=${PIP}'
	@echo '        - PIP3=${PIP3}'
	@echo '        - PACKAGE_PREFIX=${PACKAGE_PREFIX}'
	@echo '        - HOST_USER=${HOST_USER}'
	@echo '        - HOST_UID=${HOST_UID}'
	@echo '        - SERVICE_TARGET=${SERVICE_TARGET}'
	@echo '        - DOCKER_COMPOSE=${DOCKER_COMPOSE}'
	@echo '        - GIT_USER_NAME=${GIT_USER_NAME}'
	@echo '        - GIT_USER_EMAIL=${GIT_USER_EMAIL}'
	@echo '        - GIT_SERVER=${GIT_SERVER}'
	@echo '        - GIT_PROFILE=${GIT_PROFILE}'
	@echo '        - GIT_BRANCH=${GIT_BRANCH}'
	@echo '        - GIT_HASH=${GIT_HASH}'
	@echo '        - GIT_PREVIOUS_HASH=${GIT_PREVIOUS_HASH}'
	@echo '        - GIT_REPO_ORIGIN=${GIT_REPO_ORIGIN}'
	@echo '        - GIT_REPO_NAME=${GIT_REPO_NAME}'
	@echo '        - GIT_REPO_PATH=${GIT_REPO_PATH}'
	@echo '        - NOCACHE=${NOCACHE}'
	@echo '        - VERBOSE=${VERBOSE}'
	@echo '        - PASSWORD=${PASSWORD}'
	@echo '        - CMD_ARGUMENTS=${CMD_ARGUMENTS}'

#######################

ORIGIN_DIR:=$(PWD)
MACOS_TARGET_DIR:=/var/root/$(PROJECT_NAME)
LINUX_TARGET_DIR:=/root/$(PROJECT_NAME)
export ORIGIN_DIR
export TARGET_DIR

.PHONY: all venv test-venv init
all: init## 	all
venv:## 	create python3 virtualenv .venv
	test -d .venv || $(PYTHON3) -m virtualenv ENV
	( \
       virtualenv -p python3 ENV; \
       . ENV/bin/activate; \
       pip install -r requirements.txt; \
       pip install -r testing/requirements.txt; \
	);
	@echo "To activate (ENV)"
	@echo "try:"
	@echo ". ENV/bin/activate"
	@echo "or:"
	@echo "make test-venv"
test-venv:## 	test virutalenv .venv
	# insert test commands here
	test -d .venv || $(PYTHON3) -m virtualenv ENV
	( \
       virtualenv -p python3 ENV; \
       . ENV/bin/activate; \
       pip install -r testing/requirements.txt; \
       pytest testing/. \
	);
.PHONY: init
init: venv## 	basic setup
	git config --global --add safe.directory $(PWD)
	git submodule update --init --recursive
	$(PYTHON3) -m pip install --upgrade pip 2>/dev/null
	$(PYTHON3) -m pip install -q -r requirements.txt 2>/dev/null

.PHONY: build
build: init
	$(DOCKER_COMPOSE) $(VERBOSE) build --pull $(PARALLEL) --no-rm $(NOCACHE)
#######################
.PHONY: docs
docs: init
	@echo "Use 'make docs nocache=true' to force docs rebuild..."

	echo "## MAKE COMMAND" >> MAKE.md
	echo '```' > MAKE.md
	make help >> MAKE.md
	echo '```' >> MAKE.md

#.PHONY: run
#run: build
#	@echo 'run'
#ifeq ($(CMD_ARGUMENTS),)
#	@echo '$(CMD_ARGUMENTS)'
#	$(DOCKER_COMPOSE) $(VERBOSE) -p $(PROJECT_NAME)_$(HOST_UID) run -d --publish $(PUBLIC_PORT):3000 --publish 8125:8125 --publish 8126:8126 --publish 8333:8333 --publish 8332:8332 statoshi sh
#	@echo ''
#else
#	@echo ''
#	$(DOCKER_COMPOSE) $(VERBOSE) -p $(PROJECT_NAME)_$(HOST_UID) run -d --publish $(PUBLIC_PORT):3000 --publish 8125:8125 --publish 8126:8126 --publish 8333:8333 --publish 8332:8332 statoshi sh -c "$(CMD_ARGUMENTS)"
#	@echo ''
#endif
#	@echo 'Give grafana a few minutes to set up...'
#	@echo 'http://localhost:$(PUBLIC_PORT)'
########################
.PHONY: clean
clean:
	# remove created images
	@$(DOCKER_COMPOSE) -p $(PROJECT_NAME) down --remove-orphans --rmi all 2>/dev/null \
	&& echo 'Image(s) for "$(PROJECT_NAME)" removed.' \
	|| echo 'Image(s) for "$(PROJECT_NAME)" already removed.'
#######################
.PHONY: prune-system prune-network
prune-system:## 	docker system prune -af (very destructive!)
	$(DOCKER_COMPOSE) -p $(PROJECT_NAME) down
	docker system prune -af &
#######################
prune-network:## 	remove $(PROJECT_NAME) network
	$(DOCKER_COMPOSE) -p $(PROJECT_NAME) down
	docker network rm $(PROJECT_NAME)* 2>/dev/null || echo
#######################
.PHONY: push
push:
	@echo push
	git checkout -b $(TIME)/$(GIT_PREVIOUS_HASH)/$(GIT_HASH)
	git push --set-upstream origin $(TIME)/$(GIT_PREVIOUS_HASH)/$(GIT_HASH)
	git add docs
	git commit --amend --no-edit --allow-empty || echo failed to commit --amend --no-edit
	git push -f origin $(TIME)/$(GIT_PREVIOUS_HASH)/$(GIT_HASH):$(TIME)/$(GIT_PREVIOUS_HASH)/$(GIT_HASH)

SIGNIN=randymcmillan
export SIGNIN

.PHONY: signin package-docker package-all
signin:
	bash -c 'cat ~/GH_TOKEN.txt | docker login ghcr.io -u $(GIT_PROFILE) --password-stdin'
#Place a file named GH_TOKEN.txt in your $HOME - create in https://github.com/settings/tokens (Personal access tokens)
package-docker: signin
	bash -c 'docker tag  $(PROJECT_NAME)              $(PACKAGE_PREFIX)/$(GIT_PROFILE)/$(PROJECT_NAME)/$(TRIPLET)/$(HOST_USER):$(TIME) || echo skip'
	bash -c 'docker push                              $(PACKAGE_PREFIX)/$(GIT_PROFILE)/$(PROJECT_NAME)/$(TRIPLET)/$(HOST_USER):$(TIME) || echo skip'
.PHONY: package-all
package-all: init package-docker
#INSERT other scripting here
	bash -c "echo insert more scripting here..."
