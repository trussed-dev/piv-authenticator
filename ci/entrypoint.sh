#!/bin/sh

set -e
mkdir -p /app/.cache
if [ ! -e "$CARGO_HOME" ]
then
	cp -r /usr/local/cargo $CARGO_HOME
fi
pcscd
exec "$@"
