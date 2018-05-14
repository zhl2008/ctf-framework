#!/bin/sh

mitmproxy -s filter.py -p 8081  -e --no-upstream-cert  --insecure
