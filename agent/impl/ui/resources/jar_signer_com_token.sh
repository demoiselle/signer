#!/bin/bash


#Colocar o caminho do java home
JAVA_HOME=/usr/lib/jvm/java-7-serpro


PATH=$JAVA_HOME/bin:$PATH

#Colocar o Pin do Token aqui
PASSWORD="senha"

#
DSANAME="SERPRO"

#Apontar para o caminho onde estão os jars  que devem ser assinados
JARPATH="~/git/signer/agent/impl/ui/resources"

for jarfile in $(ls $JARPATH/*.jar); do
    jarfile_signed="${jarfile%.jar}-assinado.jar"
    echo "Gerando jar assinado para $jarfile em $jarfile_signed"

    #apelido do certificado, rodar o script uma primeira vez no console e copiar o apelido para este script
    ALIAS="SERVICO FEDERAL DE PROCESSAMENTO DE DADOS SERPRO:CETEC's Autoridade Certificadora do SERPRO Final v3 ID"
	    

    #lista os dados do token, inclusive o apelido
    keytool -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -list

    #assina o jar
    jarsigner -keystore NONE -storetype PKCS11 -providerClass sun.security.pkcs11.SunPKCS11 -providerArg drivers.config -storepass $PASSWORD -sigfile $DSANAME -signedjar $jarfile_signed -verbose $jarfile "$ALIAS"
done

exit 0