#!/bin/bash

url=localhost
port=8001
noproxy=${url}
ref="{\"message\":\"Hello World, root cert api\"}"

name="http on localhost:${port} (no proxy)"
result=$(curl http://${url}:${port} --noproxy ${noproxy} 2> /dev/null)

if [ "${ref}" == "${result}" ];
then
  echo "Pass: ${name}"
else
  echo "Fail: ${name}"
fi

url=$( hostname )
noproxy=${url}
name="http on ${url}:${port} (no proxy)"
result=$(curl http://${url}:${port} --noproxy ${noproxy}  2> /dev/null)

if [ "${ref}" == "${result}" ];
then
  echo "Pass: ${name}"
else
  echo "Fail: ${name}"
fi

url=localhost
noproxy=localhost
name="http on ${url}:${port} healthcheck - no proxy"
result=$(curl http://${url}:${port}/health --cacert ./certs/root_cert_cert.pem --noproxy ${noproxy} 2> /dev/null)
ref_health="\"Healthy: OK\""

if [ "\"${ref_health}\"" == "\"${result}\"" ];
then
  echo "Pass: ${name}"
else
  echo "Fail: ${name} - result: ${result} - ref_health: ${ref_health}"
fi



