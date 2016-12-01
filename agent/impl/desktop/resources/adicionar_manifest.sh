#/bin/bash

# modifica Manifest.MF dos arquivos .jar
echo "*** modificando os arquivos .jar ..."

jar ufm sad.jar manifest-addition.txt


read -s -n 1 -p "Press any key to continue…"

echo "*** Fim!"





