#!/bin/sh
set -e
echo ""
echo "---------------------------------------"
echo "          mozilla pod init"
echo "---------------------------------------"
echo ""
echo "removing stale mozilla directory"
rm -rf /podhome/.mozilla
echo "removing cache"
rm -rf /podhome/.cache
echo "installing fresh profile"
cp -rf /podhome/.pods/profiles/.mozilla /podhome

exit 0
