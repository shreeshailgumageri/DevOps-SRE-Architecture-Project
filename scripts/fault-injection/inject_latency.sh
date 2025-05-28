#!/bin/bash
# Simulate latency for chaos engineering
tc qdisc add dev eth0 root netem delay 200ms