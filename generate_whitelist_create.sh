#!/bin/sh

# Ensure some files have been passed.
./generate_whitelist.sh "$*" > ipmiwhitelist.cpp
