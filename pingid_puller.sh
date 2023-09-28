#!/bin/bash
# this it the wrapper to call the pingid_puller.py to retrieve/consume all pingid reports
set -e
set -a

# .config/pingid.cfg
declare -a ALLOW_LIST=( pingid admin_login admin_activity pingid_admin_activity sso )

for THIS_SERVICE in "${ALLOW_LIST[@]}"
do
   echo "${THIS_SERVICE}"
   # call until the return code is different than 20 mean no more logs to get
   while python3 /opt/splunk/pingid/pingid_puller.py \
                            -a "${THIS_SERVICE}"; [[ $? -eq 20 ]] ;
    do sleep 1; done
done
