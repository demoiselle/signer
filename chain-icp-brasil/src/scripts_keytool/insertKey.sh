#/bin/bash!
for i in `cat config.ini`; do
   V=$(echo ${i} | cut -f 1 -d '=' );
   A=$(echo ${i} | cut -f 2 -d '=' | envsubst);
   export ${V}=${A};
done;
RESP='yes'
keytool -import -alias ${1} -keystore ${cacerts} -trustcacerts -file ${2} -storepass ${password} -noprompt  << EOF
${RESP}
EOF
