#/bin/bash!
for i in `cat config.ini`; do
   V=$(echo ${i} | cut -f 1 -d '=' );
   A=$(echo ${i} | cut -f 2 -d '=' | envsubst);
   export ${V}=${A};
done;

keytool -v -delete -alias ${1} -keystore ${cacerts} << EOF
${password}
EOF
