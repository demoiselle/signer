#!/bin/bash

dir="/home/80621732915/Downloads/scripts_keytool/cadeias/"
for file in $(find $dir* -name "*.*" )
do
  echo "${file##*/}" $file > alias_files.txt
  ./insertKey.sh  "${file##*/}" $file
done



