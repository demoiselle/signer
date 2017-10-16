#!/bin/bash

dir="novascadeias/"
for file in $(find $dir* -name "*.*" )
do
  echo "${file##*/}" $file > alias_files.txt
  ./insertKey.sh  "${file##*/}" $file
done

