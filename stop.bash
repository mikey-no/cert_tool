#!/bin/bash

app_name=cert_tool_api
image_name=${app_name}_image
container_name=${app_name}_container

echo Stopping ${container_name}
sudo docker stop "$(sudo docker ps --filter "name=${container_name}" --all -q)"