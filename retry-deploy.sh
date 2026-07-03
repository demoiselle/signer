#!/bin/bash
export JAVA_HOME=/home/s932743005/.sdkman/candidates/java/8.0.492-tem
export PATH=$JAVA_HOME/bin:$PATH

cd /home/s932743005/repo/signer-evandrojr/

for i in {1..20}; do
    echo "Attempting deploy #$i..."
    # Skipping javadoc to speed up and avoid timeouts
    mvn clean deploy -Dmaven.test.skip=true -Dmaven.javadoc.skip=true -B \
        -Dgpg.passphrase="" \
        -Dgpg.arguments="--pinentry-mode loopback" \
        -Dmaven.wagon.http.retryHandler.count=5 \
        -Dmaven.wagon.http.connectionTimeout=600000 \
        -Dmaven.wagon.http.readTimeout=600000 \
        -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn
    
    if [ $? -eq 0 ]; then
        echo "Deploy successful!"
        exit 0
    fi
    echo "Deploy failed. Retrying in 15 seconds..."
    sleep 15
done

echo "Failed after many attempts."
exit 1
