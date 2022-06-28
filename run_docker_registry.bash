#!/bin/bash

app_name=registry
image_name=${app_name}
image_digest=sha256:bedef0f1d248508fe0a16d2cacea1d2e68e899b2220e2258f1b604e1f327d475
container_name=${app_name}_container
app_port=5000
storage_root=/mnt/${app_name}
storage=${storage_root}/data
certs_storage=${storage_root}/certs

d_images=0
d_images=$( sudo docker images -f dangling=true -q | wc -l )
if [ "${d_images}" == "0" ];
then
  echo "Clean out dangling images: ${d_images}"
  sudo docker rmi "$(sudo docker images -f dangling=true -q)"
fi

function pull_app() {
  images=0
  images=$( sudo docker images ${image_name} -q | wc -l )
  if [ "${images}" == "0" ];
  then
    echo "Pulling the image: ${image_name}"
    sudo docker pull ${image_name}:${image_digest}
  else
    echo "Registry already pulled: ${image_name}"
  fi
}

function setup_volumes(){
  if [ -d ${storage} ];
  then
    echo "Creating storage volume: ${storage}"
    mkdir -p ${storage}
  fi
  if [ -d ${certs_storage} ];
  then
    echo "Creating certs storage volume: ${certs_storage}"
    mkdir -p ${certs_storage}
  fi
}

function run_app() {
  setup_volumes
  echo "Running ${container_name}"
  docker run -d \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:${app_port} \
  --publish ${app_port}:${app_port} \
  --restart=always \
  --name ${container_name} \
  --volume ${storage}:/var/lib/registry \
  ${image_name}:latest
  #  -e REGISTRY_HTTP_TLS_CERTIFICATE=/run/secrets/domain.crt \
  #  -e REGISTRY_HTTP_TLS_KEY=/run/secrets/domain.key \
}

pull_app

container_count=0
container_count=$(docker ps --filter "name=${container_name}" --all -q | wc -l)

if [ "${container_count}" == "0" ];
then
  run_app
else
  sudo docker stop "$(docker ps --filter "name=${container_name}" --all -q )"
  sudo docker rm "$(docker ps --filter "name=${container_name}" --all -q )"
  run_app
fi

