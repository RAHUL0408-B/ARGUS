#!/bin/sh
# One-time lab setup for a fresh stack:
#  1. DVWA has no DB yet (every page redirects to setup) -> create it.
#  2. Log in to DVWA and confirm security=low (DVWA's own default).
#  3. Register that session with ZAP as a Replacer rule, so ZAP's spider/active scan
#     (which never fills in a login form on its own) rides an authenticated session
#     and actually reaches /vulnerabilities/* instead of bouncing off login.php.
# Safe to re-run: it only resets the lab DB and refreshes the ZAP rule.
docker exec argus-tools sh -c '
J=/tmp/dvwa.jar; rm -f $J
T=$(curl -s -c $J http://10.77.0.10/setup.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1)
curl -s -b $J -c $J -o /dev/null -d "create_db=Create+%2F+Reset+Database&user_token=$T" http://10.77.0.10/setup.php
curl -s -o /dev/null -w "DVWA setup -> HTTP %{http_code}\n" http://10.77.0.10/login.php

LT=$(curl -s -c $J http://10.77.0.10/login.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1)
curl -s -b $J -c $J -o /dev/null -d "username=admin&password=password&Login=Login&user_token=$LT" http://10.77.0.10/login.php
SID=$(grep PHPSESSID $J | awk "{print \$7}")
if [ -z "$SID" ]; then echo "DVWA login -> FAILED (no session)"; exit 0; fi
echo "DVWA login -> session $SID"

i=0
while [ $i -lt 20 ]; do
  curl -s -H "Host: zap" http://10.77.0.3:8090/JSON/core/view/version/ >/dev/null 2>&1 && break
  i=$((i+1)); sleep 2
done
curl -s -G "http://10.77.0.3:8090/JSON/replacer/action/removeRule/" -H "Host: zap" --data-urlencode "description=dvwa-auth" >/dev/null
curl -s -G "http://10.77.0.3:8090/JSON/replacer/action/addRule/" -H "Host: zap" \
  --data-urlencode "description=dvwa-auth" \
  --data-urlencode "enabled=true" \
  --data-urlencode "matchType=REQ_HEADER" \
  --data-urlencode "matchRegex=false" \
  --data-urlencode "matchString=Cookie" \
  --data-urlencode "replacement=PHPSESSID=${SID}; security=low" \
  --data-urlencode "initiators=" \
  --data-urlencode "url=10.77.0.10" \
  -w "\nZAP DVWA auth rule -> %{http_code}\n"
'
