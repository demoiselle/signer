#!/bin/zsh
set -e
git checkout -b 4.5.0-SNAPSHOT
sdk use java 8.0.452-tem
sdk use maven 3.8.8
mvn versions:set -DnewVersion=4.5.0-SNAPSHOT -DgenerateBackupPoms=false
mvn clean install

 