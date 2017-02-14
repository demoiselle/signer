#/bin/bash

# modifica Manifest.MF dos arquivos .jar
echo "*** modificando os arquivos .jar ..."

# jar ufm jar-file manifest-addition.txt

jar ufm log4j-1.2.16.jar manifest-addition.txt
jar ufm slf4j-log4j12-1.6.1.jar manifest-addition.txt
jar ufm slf4j-api-1.6.1.jar manifest-addition.txt

read -s -n 1 -p "Press any key to continue…"

echo "*** Fim!"





