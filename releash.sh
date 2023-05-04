#!/bin/bash
set -e
go build -o randomproxy
docker build -t xyhelper/randomproxy:latest .
docker push xyhelper/randomproxy:latest
