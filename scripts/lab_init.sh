#!/bin/sh
# One-time lab setup for a fresh stack:
#  1. DVWA has no DB yet (every page redirects to setup) -> create it.
#  2. Log in to DVWA and confirm security=low (DVWA's own default).
#  3. Register the DVWA login as a ZAP HTTP Session, so ZAP's spider/active scan (which never
#     fills in a login form on its own) rides an authenticated session and actually reaches
#     /vulnerabilities/* instead of bouncing off login.php. A ZAP Replacer rule looks like the
#     right tool but only REPLACES a Cookie header that already exists -- it never ADDS one, so
#     it silently did nothing on a fresh ZAP daemon. httpSessions is the API actually built to
#     force cookies onto every request. (A `core/newSession` reset was tried here too, on the
#     theory that ZAP's spider might remember an earlier unauthenticated crawl of the same host
#     and not revisit it -- testing showed that theory was wrong and the reset actively broke
#     httpSessions instead, so it was removed.)
#  4. VERIFY it actually worked: spider the host and check /vulnerabilities/sqli shows up in
#     what ZAP discovered. This setup has occasionally needed a second attempt in testing (the
#     exact cause wasn't pinned down with confidence -- plausibly DVWA/ZAP startup timing under
#     load) so rather than trust it blindly, retry the whole login+session sequence up to 3
#     times until the verification actually passes, and say clearly if it never does.
# Safe to re-run: it only resets the lab DB and ZAP's own session state, never DVWA/Juice Shop data.
docker exec argus-tools sh -c '
Z="http://10.77.0.3:8090"; SITE="http://10.77.0.10"

i=0
while [ $i -lt 20 ]; do
  curl -s -H "Host: zap" "$Z/JSON/core/view/version/" >/dev/null 2>&1 && break
  i=$((i+1)); sleep 2
done

attempt=1
ok=0
while [ $attempt -le 3 ]; do
  echo "--- lab_init attempt $attempt ---"
  J=/tmp/dvwa.jar; rm -f $J
  T=$(curl -s -c $J http://10.77.0.10/setup.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1)
  curl -s -b $J -c $J -o /dev/null -d "create_db=Create+%2F+Reset+Database&user_token=$T" http://10.77.0.10/setup.php
  curl -s -o /dev/null -w "DVWA setup -> HTTP %{http_code}\n" http://10.77.0.10/login.php

  LT=$(curl -s -c $J http://10.77.0.10/login.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1)
  curl -s -b $J -c $J -o /dev/null -d "username=admin&password=password&Login=Login&user_token=$LT" http://10.77.0.10/login.php
  SID=$(grep PHPSESSID $J | awk "{print \$7}")
  if [ -z "$SID" ]; then echo "DVWA login -> FAILED (no session), retrying"; attempt=$((attempt+1)); sleep 3; continue; fi
  echo "DVWA login -> session $SID"

  curl -s -G "$Z/JSON/replacer/action/removeRule/" -H "Host: zap" --data-urlencode "description=dvwa-auth" >/dev/null
  curl -s -G "$Z/JSON/httpSessions/action/removeSession/" -H "Host: zap" --data-urlencode "site=$SITE" --data-urlencode "session=dvwa" >/dev/null
  curl -s -G "$Z/JSON/httpSessions/action/createEmptySession/" -H "Host: zap" --data-urlencode "site=$SITE" --data-urlencode "session=dvwa" >/dev/null
  curl -s -G "$Z/JSON/httpSessions/action/setSessionTokenValue/" -H "Host: zap" --data-urlencode "site=$SITE" --data-urlencode "session=dvwa" --data-urlencode "sessionToken=PHPSESSID" --data-urlencode "tokenValue=$SID" >/dev/null
  curl -s -G "$Z/JSON/httpSessions/action/setSessionTokenValue/" -H "Host: zap" --data-urlencode "site=$SITE" --data-urlencode "session=dvwa" --data-urlencode "sessionToken=security" --data-urlencode "tokenValue=low" >/dev/null
  curl -s -G "$Z/JSON/httpSessions/action/setActiveSession/" -H "Host: zap" --data-urlencode "site=$SITE" --data-urlencode "session=dvwa" -w "ZAP DVWA session -> %{http_code}\n"

  # Verify: spider the host, then check /vulnerabilities/sqli is reachable (i.e. the session really authenticated the crawl).
  SCANID=$(curl -s -G "$Z/JSON/spider/action/scan/" -H "Host: zap" --data-urlencode "url=$SITE" --data-urlencode "recurse=true" --data-urlencode "maxChildren=60" | sed -n "s/.*\"scan\":\"\([0-9]*\)\".*/\1/p")
  w=0
  while [ $w -lt 15 ]; do
    st=$(curl -s "$Z/JSON/spider/view/status/?scanId=$SCANID" -H "Host: zap" | sed -n "s/.*\"status\":\"\([0-9]*\)\".*/\1/p")
    [ "$st" = "100" ] && break
    w=$((w+1)); sleep 2
  done
  found=$(curl -s -G "$Z/JSON/core/view/urls/" -H "Host: zap" --data-urlencode "baseurl=$SITE" | grep -c "vulnerabilities/sqli")
  if [ "$found" -gt 0 ]; then
    echo "Verify -> OK: authenticated crawl reached /vulnerabilities/sqli"
    ok=1
    break
  fi
  echo "Verify -> FAILED: authenticated pages not reached, retrying setup"
  attempt=$((attempt+1)); sleep 3
done
if [ "$ok" != "1" ]; then
  echo "lab_init: could not get an authenticated ZAP crawl of DVWA after 3 attempts. An active scan run now will likely find 0 injection findings -- re-run this script, or check the lab containers are healthy."
fi
'
