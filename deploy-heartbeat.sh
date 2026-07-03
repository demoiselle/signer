#!/bin/bash
export JAVA_HOME=/home/s932743005/.sdkman/candidates/java/8.0.492-tem
export PATH=$JAVA_HOME/bin:$PATH
cd /home/s932743005/repo/signer-evandrojr/
mvn clean deploy -Dmaven.test.skip=true -Dmaven.javadoc.skip=true -Dgpg.skip=true -B \
    -Dmaven.wagon.http.retryHandler.count=5 \
    -Dmaven.wagon.http.connectionTimeout=300000 \
    -Dmaven.wagon.http.readTimeout=300000 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    echo "Deployment in progress..."
    sleep 60
done
wait $PID
