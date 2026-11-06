# One-time DVWA database setup for a fresh lab (without it every DVWA page redirects to setup). Re-running resets only the lab DB.
$script = @'
J=/tmp/dvwa.jar; rm -f $J
T=$(curl -s -c $J http://10.77.0.10/setup.php | sed -n "s/.*user_token. value=.\([a-f0-9]*\).*/\1/p" | head -1)
curl -s -b $J -c $J -o /dev/null -d "create_db=Create+%2F+Reset+Database&user_token=$T" http://10.77.0.10/setup.php
curl -s -o /dev/null -w "DVWA setup -> HTTP %{http_code}\n" http://10.77.0.10/login.php
'@
$script | docker exec -i argus-tools sh
