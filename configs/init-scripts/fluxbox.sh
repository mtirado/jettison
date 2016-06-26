#!/bin/bash
# Init script for Xephyr pods to run Fluxbox as window manager.
# You Will need to whitelist your shell and associated system calls
# for your window manager of choice. Fluxbox is fairly light weight.

set -e
fluxbox & sleep 3

# can check if WM is still running here for proper error handling.
