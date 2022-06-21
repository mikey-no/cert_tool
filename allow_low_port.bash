#!/bin/bash

function allow_low_port(){

  echo "Allow a non privileged user to bind to port 80 (or any port less that 1024)"
  name=${1}
  exe_path=$(which ${name})
  exe_dir=$(dirname ${exe_path})

  exe_enabled=${exe_dir}/${name}_enabled

  echo "${name} ${exe_path}"
  echo "${name} is this directory: ${exe_dir}"

  echo "copy ${name} to a local file without a link"
  cp ${exe_path} ${exe_enabled}

  echo "Enable this enabled copy of ${name} the new permission"
  sudo setcap cap_net_bind_service=ep ${exe_enabled}

  echo "Get capability of ${exe_enabled}"
  sudo getcap ${exe_enabled}
}

allow_low_port python