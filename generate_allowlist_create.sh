#!/bin/sh

# Ensure some files have been passed.
./generate_allowlist.sh "$*" > ipmiallowlist.cpp
