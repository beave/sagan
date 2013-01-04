#!/usr/bin/env bash

<<LICENSE
Copyright (c) 2012, shadowbq@gmail.com 
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, 
  this list of conditions and the following disclaimer in the documentation 
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTOR BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
THE POSSIBILITY OF SUCH DAMAGE.

LICENSE

### CONFIG ###

SAGAN_CONF=/usr/local/etc/sagan.conf
SAGAN_REPO_URL=https://github.com/beave/sagan-rules.git

TMP_DIR=/tmp

### FUNCTIONS ###

usage()
{
cat << EOF
usage: $0 options

This command will assist in downloading and updating sagan-rules rulebase, and map files. 

OPTIONS:
   -f, --file		Sagan configuration file location	
		  	  default: $SAGAN_CONF  	
   -u, --url		Sagan-rule git repo url 
		  	  default: $SAGAN_REPO_URL  	

GENERIC:
   -v, --verbose  	Verbose
   -h, --help		Show this message
EOF
}

validate_rulebase() {
  if [ ! -d "$1" ]; then
    echo >&2 "Sagan rulebase ($1) not found."; exit 1;
  fi
  if [ ! $(ls -l $1/*.rulebase | grep -v total | wc -l) -gt 0 ]; then
    echo >&2 "Sagan rulebase contents not found. Aborting."; exit 1;
  fi
}

# find or set up a working git environment
git_sagan_check() {
  D_GIT_CLONE_PATH=$TMP_DIR/sagan_rules

  test -d "$D_GIT_CLONE_PATH" \
    && cd "$D_GIT_CLONE_PATH" \
    && git status > /dev/null 2>&1  # folder exists? go there. is a good git clone?
  if [ $? -ne 0 ]; then
    # not a git repo, create it?
    echo "the folder ($D_GIT_CLONE_PATH) you specified does not exist or doesn't contain a git repo.. fetching"
    mkdir -p -v "$D_GIT_CLONE_PATH"  # only if it doesn't exist
    if [ -z "$B_VERBOSE" ]; then
      git clone --quiet "$SAGAN_REPO_URL" "$D_GIT_CLONE_PATH"
    else
      git clone "$SAGAN_REPO_URL" "$D_GIT_CLONE_PATH"
    fi  
  else
    if [ -z "$B_VERBOSE" ]; then
      git checkout --quiet master
      git pull --quiet
    else
      git checkout master
      git pull 
    fi
  fi

  # Validate the pull
  validate_rulebase "$D_GIT_CLONE_PATH"
  
  if [ -n "$B_VERBOSE" ]; then
    echo "Finished pulling sagan rules."
  fi
}

validate_system() {
  if [ ! -f $SAGAN_CONF ];
  then
    echo >&2 "Sagan configuration is not found. Aborting."; exit 1;
  fi

  A_REQUIRED_COMMANDS=( git awk )
  for i in "${A_REQUIRED_COMMANDS[@]}"
  do
    command -v $i >/dev/null 2>&1 || { echo >&2 "I require $i but it's not installed.  Aborting."; exit 1; }
  done

  D_CONFIG_DIR=`awk '/(var RULE_PATH )(.*)/ {print $3}' $SAGAN_CONF`

  if [ ! -d "$D_CONFIG_DIR" ]; then
    echo >&2 "Sagan configuration directory ($D_CONFIG_DIR) not found. Aborting."; exit 1;
  fi

  if [ ! -w "$D_CONFIG_DIR/." ]; then
    echo >&2 "Sagan configuration directory ($D_CONFIG_DIR) not writable. Aborting."; exit 1;
  fi

  if [ ! -w "$TMP_DIR/." ]; then
    echo >&2 "tmp directory ($TMP_DIR) not writable. Aborting."; exit 1;
  fi
}

copy_rulebase() {
  cp -f $D_GIT_CLONE_PATH/*.rulebase $D_CONFIG_DIR
  validate_rulebase "$D_CONFIG_DIR"
}

copy_configs() {
  cp -f $D_GIT_CLONE_PATH/*.config $D_CONFIG_DIR
  validate_rulebase "$D_CONFIG_DIR"
}

### PERFORM ###

for arg
do
    delim=""
    case "$arg" in
       --help) args="${args}-h ";;
       --verbose) args="${args}-v ";;
       --file) args="${args}-f ";;
       --url) args="${args}-u ";;
       # pass through anything else
       *) [[ "${arg:0:1}" == "-" ]] || delim="\""
           args="${args}${delim}${arg}${delim} ";;
    esac
done

# reset the translated args
eval set -- $args
# now we can process with getopt

while getopts "f:u:hv" opt; do
    case $opt in
        f)                      SAGAN_CONF=$OPTARG
                                ;;
        u)    	                SAGAN_REPO_URL=$OPTARG
                                ;;
        v)                      B_VERBOSE=1
                                ;;
        h)                      usage
                                exit
                                ;;
        * )                     usage
                                exit 1
    esac
done

validate_system

git_sagan_check

copy_rulebase

copy_configs

if [ -n "$B_VERBOSE" ]; then
  echo -e "Sagan rulebase and config update complete. \n (Note: Sagan *.rules were not updated. Use pulledpork for this process.)"
fi

exit 0;