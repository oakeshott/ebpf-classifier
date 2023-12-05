#!/usr/bin/env sh

######################################################################
# @author      : t-hara (t-hara@$HOSTNAME)
# @file        : release-cpus
# @created     : Wednesday Mar 01, 2023 04:03:55 UTC
#
# @description : 
######################################################################
CPU_LIST=`seq 1 23`
for i in $CPU_LIST
do
  sudo chcpu -e $i
done

