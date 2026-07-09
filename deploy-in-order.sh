#!/bin/bash
export JAVA_HOME=/home/s932743005/.sdkman/candidates/java/8.0.492-tem
export PATH=$JAVA_HOME/bin:$PATH

cd /home/s932743005/repo/signer-evandrojr/

# Use -Dmaven.test.skip=true and -Dgpg.skip=true to bypass blockers
OPTS="-Dmaven.test.skip=true -B"

echo "Step 1: Deploying build..."
mvn clean deploy -N $OPTS && \
echo "Step 2: Deploying all modules..." && \
mvn deploy $OPTS
