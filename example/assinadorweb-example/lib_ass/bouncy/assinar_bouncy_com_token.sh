#!/bin/bash

clear

## SETAR O JAVA HOME em .bashrc
echo $JAVA_HOME


#Colocar o Pin do Token aqui
PASSWORD=""

#NAO ALTERAR!
DSANAME="SERPRO"

#Apontar para o caminho onde estão os jars  que devem ser assinados
JARPATH="/home/80621732915/git/signer/example/assinadorweb-example/resources/bouncy"
JARPATH_ASS="/home/80621732915/git/signer/example/assinadorweb-example/resources/bouncy/assinados/"


for jarfile in $(ls $JARPATH/*.jar); do
    jarfile_signed="${jarfile%.jar}-assinado.jar"
    echo "Gerando jar assinado para $jarfile em $jarfile_signed"

    #Alias do certificado, rodar o script uma primeira vez no console e copiar o apelido cara este script
    ALIAS="SERVICO FEDERAL DE PROCESSAMENTO DE DADOS SERPRO:CETEC's Autoridade Certificadora do SERPRO Final v3 ID"
	    

    #lista os dados do token, inclusive o apelido
    keytool -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -list

    #assina o jar  
    jarsigner -digestalg SHA-1 -J-Djava.security.debug=sunpkcs11 -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -sigfile $DSANAME -signedjar $jarfile_signed -verbose $jarfile "$ALIAS"
done

exit 0
