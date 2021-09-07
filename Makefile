SHELL									:= /bin/bash

PWD 									?= pwd_unknown

THIS_FILE								:= $(lastword $(MAKEFILE_LIST))
export THIS_FILE
TIME									:= $(shell date +%s)
export TIME

ARCH									:= $(shell uname -m)
export ARCH

ifeq ($(user),)
HOST_USER								:= root
HOST_UID								:= $(strip $(if $(uid),$(uid),0))
else
HOST_USER								:=  $(strip $(if $(USER),$(USER),nodummy))
HOST_UID								:=  $(strip $(if $(shell id -u),$(shell id -u),4000))
endif
export HOST_USER
export HOST_UID

ifeq ($(target),)
SERVICE_TARGET							?= shell
else
SERVICE_TARGET							:= $(target)
endif
export SERVICE_TARGET

ifeq ($(docker),)
#DOCKER									:= $(shell find /usr/local/bin -name 'docker')
DOCKER									:= $(shell which docker)
else
DOCKER									:= $(docker)
endif
export DOCKER

ifeq ($(compose),)
#DOCKER_COMPOSE							:= $(shell find /usr/local/bin -name 'docker-compose')
DOCKER_COMPOSE							:= $(shell which docker-compose)
else
DOCKER_COMPOSE							:= $(compose)
endif
export DOCKER_COMPOSE

ifeq ($(alpine),)
ALPINE_VERSION							:= 3.11.6
else
ALPINE_VERSION							:= $(alpine)
endif
export ALPINE_VERSION

# PROJECT_NAME defaults to name of the current directory.
ifeq ($(project),)
PROJECT_NAME							:= $(notdir $(PWD))
else
PROJECT_NAME							:= $(project)
endif
export PROJECT_NAME

#GIT CONFIG
GIT_USER_NAME							:= $(shell git config user.name)
export GIT_USER_NAME
GIT_USER_EMAIL							:= $(shell git config user.email)
export GIT_USER_EMAIL
GIT_SERVER								:= https://github.com
export GIT_SERVER

GIT_REPO_NAME							:= $(PROJECT_NAME)
export GIT_REPO_NAME

ifeq ($(GH_PROFILE),)
#Usage gh-profile=<organization> make
GH_PROFILE								:= Coldcard
else
GH_PROFILE								:= $(gh-profile)
endif

GIT_BRANCH								:= $(shell git rev-parse --abbrev-ref HEAD)
export GIT_BRANCH
GIT_HASH								:= $(shell git rev-parse --short HEAD)
export GIT_HASH
GIT_PREVIOUS_HASH						:= $(shell git rev-parse --short HEAD~1)
export GIT_PREVIOUS_HASH
GIT_REPO_ORIGIN							:= $(shell git remote get-url origin)
export GIT_REPO_ORIGIN
GIT_REPO_PATH							:= $(HOME)/$(GIT_REPO_NAME)
export GIT_REPO_PATH

CKCC_GIT_BRANCH							:= $(shell set pushdsilent && pushd external/ckcc-protocol  &> /dev/null && git rev-parse HEAD)
export CKCC_GIT_BRANCH
CKCC_GIT_HASH							:= $(shell set pushdsilent && pushd external/ckcc-protocol  &> /dev/null && git rev-parse --short HEAD)
export CKCC_GIT_HASH
CKCC_GIT_PREVIOUS_HASH					:= $(shell set pushdsilent && pushd external/ckcc-protocol  &> /dev/null && git rev-parse --short HEAD~1)
export CKCC_GIT_PREVIOUS_HASH
CKCC_GIT_REPO_ORIGIN					:= $(shell set pushdsilent && pushd external/ckcc-protocol  &> /dev/null && git remote get-url origin)
export CKCC_GIT_REPO_ORIGIN
CKCC_GIT_REPO_PATH						:= $(HOME)/$(GIT_REPO_NAME)/external/ckcc-protocol
export CKCC_GIT_REPO_PATH

ifeq ($(nocache),true)
NOCACHE									:= --no-cache
else
NOCACHE									:=	
endif
export NOCACHE

ifeq ($(verbose),true)
VERBOSE									:= --verbose
else
VERBOSE									:=	
endif
export VERBOSE

ifeq ($(port),)
PUBLIC_PORT								:= 80
else
PUBLIC_PORT								:= $(port)
endif
export PUBLIC_PORT

ifneq ($(passwd),)
PASSWORD								:= $(passwd)
else 
PASSWORD								:= changeme
endif
export PASSWORD

ifeq ($(cmd),)
CMD_ARGUMENTS							:= 	
else
CMD_ARGUMENTS							:= $(cmd)
endif
export CMD_ARGUMENTS
#######################
PACKAGE_PREFIX							:= ghcr.io
export PACKAGE_PREFIX
#######################
.PHONY: init
init:
ifneq ($(shell id -u),0)
	@echo 'not sudo'
	git submodule update --init
endif
ifeq ($(shell id -u),0)
	@echo 'sudo'
endif
#######################
.PHONY: super
super:
ifneq ($(shell id -u),0)
	sudo -s
endif
#######################
.PHONY: all
all: init requirements unix
#######################
.PHONY: mpy-cross
mpy-cross:
	bash -c "pushd external/micropython/mpy-cross &> /dev/null && make && popd &> /dev/null"
#######################
.PHONY: unix
unix: mpy-cross
	#bash -c "pushd external/micropython/mpy-cross &> /dev/null && make && popd &> /dev/null"
	bash -c "pushd unix &> /dev/null && make setup ngu-setup && popd &> /dev/null"
#######################
.PHONY: simulator
simulator: unix
	bash -c "pushd unix &> /dev/null && make && ./simulator.py && popd &> /dev/null"
#######################
.PHONY: requirements
requirements:
ifneq ($(PIP3),)
	$(PIP3) install -r requirements.txt
	pushd unix  &> /dev/null && $(PIP3) install -r requirements.txt && popd &> /dev/null
	pushd docs  &> /dev/null && $(PIP3) install -r requirements.txt && popd &> /dev/null
	pushd cli   &> /dev/null && $(PIP3) install -r requirements.txt && popd &> /dev/null
else
	$(PIP) install -r requirements.txt
	pushd unix  &> /dev/null && $(PIP) install -r requirements.txt && popd &> /dev/null
	pushd docs  &> /dev/null && $(PIP) install -r requirements.txt && popd &> /dev/null
	pushd cli   &> /dev/null && $(PIP) install -r requirements.txt && popd &> /dev/null
endif
#######################
.PHONY: repro
repro:
	pushd stm32  &> /dev/null && make repro && popd &> /dev/null
#######################
.PHONY: docs
docs:
ifneq ($(PIP3),)
	pushd docs  &> /dev/null && $(PIP3) install -r requirements.txt && popd &> /dev/null
else
	pushd docs  &> /dev/null && $(PIP) install -r requirements.txt && popd &> /dev/null
endif
	mkdocs build -v -f mkdocs.yml 
	
	sudo mkdocs serve -a 127.0.0.1:$(PUBLIC_PORT) -f mkdocs.yml #& 
	#bash -c "if hash open 2>/dev/null; then open http://127.0.0.1:$(PUBLIC_PORT); fi || echo failed to open http://127.0.0.1:$(PUBLIC_PORT);"
#######################
.PHONY: clean
clean:
	@echo 'clean'
#######################
-include report.mk
-include help.mk

