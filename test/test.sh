#!/bin/bash 

if [ ${#} -eq 0 ]; then
  exit 1
fi

if [ ${1} = "-h" ]; then
  echo "${0} <wifi|eth> <FILE>"
  exit 0
fi

if [ $1 == "wifi" ]; then
  INTERFACE=wlp3s0
else 
  INTERFACE=enp2s0
fi

FILE=$2

tcpreplay -i ${INTERFACE} -K --mbps 100 ${FILE}
