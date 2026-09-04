#!/bin/bash
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
for i in `cat config.ini`; do
   V=$(echo ${i} | cut -f 1 -d '=' );
   A=$(echo ${i} | cut -f 2 -d '=' | envsubst);
   export ${V}=${A};
done;
RESP='yes'
keytool -import -alias ${1} -keystore ${cacerts} -trustcacerts -file ${2} -storetype BKS -provider org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath "${SCRIPT_DIR}/bcprov-jdk18on-1.80.jar"  -storepass ${password} -noprompt  << EOF
${RESP}
EOF
