#!/bin/sh
# Inert test fixture: a defensive hook that blocks reads of .env files.
input=$(cat)
case "$input" in
  *'.env'*) echo "Reading .env files is blocked" >&2; exit 2 ;;
esac
exit 0
