#!/bin/sh

# Ensure some files have been passed.
eval "./generate_whitelist.sh $*" > ipmiwhitelist.cpp
