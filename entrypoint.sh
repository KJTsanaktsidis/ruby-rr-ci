#!/bin/bash

set -ex;

CMD=("/usr/bin/dumb-init" "--" "$@")

# If we were given a uid/gid to drop to, use those
if ! [[ -z "$BUILD_UID" ]]; then
  export BUILD_GID="${BUILD_GID:-$BUILD_UID}"
  # We actually should create a real user for this, so that $HOME etc work properly.
  mkdir -p /run/home
  groupadd --gid="$BUILD_GID" --non-unique ruby-rr-ci
  useradd --uid="$BUILD_UID" --gid="$BUILD_GID" --home="/run/home/ruby-rr-ci" --non-unique ruby-rr-ci
  # We don't really want to clear the whole env, but we do want $USER etc
  # to be set appropriately.
  CMD=(
    "setpriv" "--reuid=${BUILD_UID}" "--regid=${BUILD_GID}" "--init-groups"
    "--" "/usr/bin/env" "HOME=/run/home/ruby-rr-ci" "LOGNAME=ruby-rr-ci"
    "${CMD[@]}"
  )
fi

# See if we can make a cgroup to run as
if mkdir -p /sys/fs/cgroup/ruby-rr-ci; then
  if ! [[ -z "$BUILD_UID" ]]; then
    chown -R "${BUILD_UID}:${BUILD_GID}" /sys/fs/cgroup/ruby-rr-ci
    CMD=("cgexec" "-g" ":/ruby-rr-ci" "${CMD[@]}")
  fi
fi

exec "${CMD[@]}"
