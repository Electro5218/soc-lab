#!/bin/bash
export IDS_WORKERS=4
export GEOIP_DB="$(dirname "$0")/GeoLite2-City.mmdb"
sudo python3 "$(dirname "$0")/ids.py"