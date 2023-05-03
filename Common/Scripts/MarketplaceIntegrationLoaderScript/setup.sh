#!/bin/bash

REPO_DIR=$(pwd)
MILS_DIR="$HOME/MILS"
CONSTS_FILE="$MILS_DIR/consts.py"
INTEGRATIONS_PATH="$(readlink -f ../../../Integrations)"
INTEGRATIONS_PY_CONST="INTEGRATIONS_FILE"
SETTINGS_FILE="$MILS_DIR/settings.conf"
SETTINGS_PY_CONST="CONFIG_FILE"


install_mils_in_user_dir(){
  echo "Copying MILS directory to $MILS_DIR..."
  if ! (mkdir -p "$MILS_DIR" && cp -R "$REPO_DIR/"* "$MILS_DIR")
  then
    echo "Error! Could not copy directory to $MILS_DIR"
    exitr 1
  else
    echo "Copying finished successfully"
  fi
  return 0
}

add_integration_path_to_consts(){
  echo "setting up marketplace/Integrations path in MILS..."

  # shellcheck disable=SC2002
  if cat "$CONSTS_FILE" | grep -iq "$INTEGRATIONS_PY_CONST"
  then
    current=$(cat "$CONSTS_FILE" | grep -i "$INTEGRATIONS_PY_CONST")
    sed -i.abk "s,$current,$INTEGRATIONS_PY_CONST = '$INTEGRATIONS_PATH',g" "$CONSTS_FILE"
  else
    echo "$INTEGRATIONS_PY_CONST = '$INTEGRATIONS_PATH'">>"$CONSTS_FILE"
  fi
  return 0
}

add_settings_path_to_consts(){
  echo "Updating local configuration path to MILS"

  # shellcheck disable=SC2002
  if cat "$CONSTS_FILE" | grep -iq "$SETTINGS_PY_CONST"
  then
    current=$(cat "$CONSTS_FILE" | grep -i "$SETTINGS_PY_CONST")
    sed -i.abk "s,$current,$SETTINGS_PY_CONST = '$SETTINGS_FILE',g" "$CONSTS_FILE"
  else
    echo "$SETTINGS_PY_CONST = '$SETTINGS_FILE'">>"$CONSTS_FILE"
  fi
  return 0
}

update_settings(){
  echo "Adding configuration settings"
  echo "Enter Siemplify instance API Root: " && read API_ROOT
  echo "Enter Username for Siemplify instance: " && read USERNAME
  echo "Enter Password for Siemplify instance: " && read -s PASSWORD

  echo "saving updated configuration settings..."
  if ! echo "\
  {
      \"api_root\": \"$API_ROOT\",
      \"username\": \"$USERNAME\",
      \"password\": \"$PASSWORD\"
  }
  ">"$MILS_DIR/settings.conf"
  then
    echo: "Error! configuration not saved. exiting process..."
    exit 1
  else
    echo "Saved configuration successfully"
  fi
  return 0
}

add_mils_alias(){
  MILS_ALIAS_PREFIX="alias mils"
  MILS_ALIAS_CMD="$MILS_ALIAS_PREFIX='python3 $MILS_DIR/mils.py'"

  if [[ "$OSTYPE" == "darwin"* ]] # check if os is macos
  then
    aliases_file="$HOME/.zshrc"
  elif [[ "$OSTYPE" == "linux-gnu"* ]]  #else, check if os is linux/unix
   then
    aliases_file="$HOME/.bashrc"
  else
    echo "unsupported operating system: $OSTYPE. Exiting process..."
    exit 1
  fi

  echo "adding mils as alias in $aliases_file..."
  # shellcheck disable=SC2002
  if cat "$aliases_file" | grep -iq "$MILS_ALIAS_PREFIX"
  then
    current=$(cat "$aliases_file" | grep -i "$MILS_ALIAS_PREFIX")
    echo "found existing alias configuration: $current"
    echo "Updating alias configuration..."
    if ! sed -i.abk "s,$current,$MILS_ALIAS_CMD,g" "$aliases_file"
    then
      echo "Error! Could no update $aliases_file. Exiting process.."
      exit 1; fi
  else
    echo "$MILS_ALIAS_CMD">>$aliases_file
  fi

#  # shellcheck disable=SC1090
#  if ! source "$aliases_file"; then exit 1; fi
  echo "added 'mils' as alias successfully"
  echo "~~~IMPORTANT~~~ Run the following command to source 'mils' in bash:
source $aliases_file

After that you will be able to use 'mils' command in the terminal."
  echo "for more information type 'mils -h' in the terminal"

  return 0
}

add_settings_read_permissions(){

  if ! chmod +r "$SETTINGS_FILE"
  then
    echo "Error! Could not add read permissions for $MILS_DIR.
Please verify that $SETTINGS_FILE have read permissions manually before running 'mils'
    "
  fi
  return 0
}

main(){
  if ! install_mils_in_user_dir; then exit 1; fi
  if ! add_integration_path_to_consts; then exit 1; fi
  if ! add_settings_path_to_consts; then exit 1; fi
  if ! update_settings; then exit 1; fi
  if ! add_mils_alias; then exit 1; fi
  if ! add_settings_read_permissions; then exit 1; fi
}

main "$@"; exit