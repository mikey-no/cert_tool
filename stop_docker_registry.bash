#!/bin/bash

app_name=registry
image_name=${app_name}
container_name=${app_name}_container

echo Stopping ${container_name}
sudo docker stop "$(sudo docker ps --filter "name=${container_name}" --all --quiet)"