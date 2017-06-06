#!/bin/bash
#
# Use this script to help override circle-ci's go inference.
#
# Set env var GOVERSION to the version of go you'd like installed. Then call this script in the
# dependencies/override build phase. Your Go version will be installed to /home/ubuntu/go in the
# container, and your project's source code will be rsync'd into the $GOPATH so that local import
# paths will resolve correctly.
#
# Add `../go` path to your dependencies/cache_directories setting in circle.yml for
# faster builds.
#
# Example circle.yml:
#
#   ---
#   machine:
#     environment:
#       GOVERSION: 1.6.1
#       GOPATH: /home/ubuntu/go_workspace
#       GOROOT: /home/ubuntu/go
#       PATH:   /home/ubuntu/go/bin:$GOPATH/bin:$PATH
#
#   dependencies:
#     cache_directories:
#       - ../go_workspace
#       - ../go
#
#     overide:
#       - bash scripts/install-go.sh
#
set -eou pipefail
CIRCLECI=${CIRCLECI:-}
GOVERSION=${GOVERSION:-}
CIRCLE_REPOSITORY_URL=${CIRCLE_REPOSITORY_URL:-}

if [ "$CIRCLECI" != "true" ]; then
  echo "This script meant to only be run on CIRCLECI"
  exit 1
fi

if [ -z "$GOVERSION" ] ; then
  echo "set GOVERSION environment var"
  exit 1
fi


function fu_circle {
  # convert CIRCLE_REPOSITORY_URL=https://github.com/user/repo -> github.com/user/repo
  local IMPORT_PATH
  IMPORT_PATH=$(sed -e 's#https://##' <<< "$CIRCLE_REPOSITORY_URL")
  sudo rm -rf /usr/local/go
  # circle creates `.go_workspace` as the GOPATH but we use our own, delete circle's if it exists
  sudo rm -rf /home/ubuntu/.go_workspace || true
  sudo ln -s "$HOME/go"  /usr/local/go
  # remove the destination dir if it exists
  if [ -d "$GOPATH/src/$IMPORT_PATH" ] ; then
    rm -rf "$GOPATH/src/$IMPORT_PATH"
  fi

  # move our new stuff into the destination
  pd=$(pwd)
  cd ../

  basedir=$(dirname  "$GOPATH/src/$IMPORT_PATH")
  if [ ! -d "$basedir" ] ; then
    mkdir -p "$basedir"
  fi
  mv "$pd" "$GOPATH/src/$IMPORT_PATH"
  ln -s "$GOPATH/src/$IMPORT_PATH" "$pd"
}

if "$HOME/go/bin/go" version 2> /dev/null | grep -q " go$GOVERSION" > /dev/null 2>&1 ; then
  echo "go $GOVERSION installed prepping go import path"
  fu_circle
  exit 0
fi

gotar=go${GOVERSION}.tar.gz
curl -o "$HOME/$gotar" "https://storage.googleapis.com/golang/go${GOVERSION}.linux-amd64.tar.gz" > /dev/null 2>&1
tar -C "$HOME/" -xzf "$HOME/$gotar" > /dev/null

fu_circle
