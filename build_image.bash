#!/bin/bash

app_name=cert_tool_api
image_name=${app_name}_image
container_name=${app_name}_container

export DOCKER_BUILDKIT=1

function rm_dangling_images () {

  echo "Remove danging images"
  sudo docker rmi $(sudo docker images -f dangling=true -q)
}

#rm_dangling_images

echo "Build the docker image: ${image_name}"
sudo docker build \
  --file ./Dockerfile \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  --tag ${image_name}:latest \
  .