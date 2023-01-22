#!/bin/bash

# Generate hosts file from blocklist/

cat ./blocklists-plain-text/* > hosts-plain-text
cat ./blocklists-regex/*      > hosts-regex


