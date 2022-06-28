#!/bin/bash

app_name=cert_tool_api
image_name=${app_name}_image
container_name=${app_name}_container
APP_PORT=8001

function create_app_user(){
  # create matching use called python (in this case) to enable to application to be run from a non privileged account
  user=python
  user_id_ref=990
  user_id=99999
  user_id_count=$(id --user ${user} 2>/dev/null  | wc -l)
  if [ "${user_id_count}" == "1" ];
  then
      echo "Non privileged user ${user} found to run the application"
  else
    echo "Adding a non privileged user and group for ${user} to run the application"
    groupadd -g ${user_id_ref} ${user}
    useradd -r -u ${user_id_ref} -g ${user} ${user}
  fi
}

function docker_run() {
  container_count=0
  container_count=$(sudo docker ps --filter "name=${container_name}" --all -q | wc -l)

  sudo docker ps --filter "name=${container_name}" --all

  if [ "${container_count}" == "0" ];
  then
    echo "------"
  else
    sudo docker stop "$(sudo docker ps --filter "name=${container_name}" --all -q )"
    sudo docker rm "$(sudo docker ps --filter "name=${container_name}" --all -q )"
  fi

  echo "Running image: ${image_name} as container:${container_name}"
  sudo docker run \
    --name ${container_name} \
    --publish ${APP_PORT}:${APP_PORT} \
    ${image_name}

  #docker logs "$(docker ps --filter "name=${container_name}" --all -q)"

}

create_app_user
docker_run

