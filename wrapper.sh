#!/bin/bash

# figuring out how to pipe into tee was way too difficult, just put it in a wrapper instead
mkdir -p script-logs
./cyber.sh | tee script-logs/main.log