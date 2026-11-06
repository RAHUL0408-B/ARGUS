#!/bin/sh
# One-time DVWA database setup (fresh container has no DB, so every page redirects to setup). Safe to re-run: it resets the lab DB only.
docker exec argus-tools sh -c '
J=/tmp/dvwa.jar; rm -f $J
T=$(curl -s -c $J http://10.77.0.10/setup.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1)
curl -s -b $J -c $J -o /dev/null -d "create_db=Create+%2F+Reset+Database&user_token=$T" http://10.77.0.10/setup.php
curl -s -o /dev/null -w "DVWA setup -> HTTP %{http_code}\n" http://10.77.0.10/login.php'
