#!/bin/bash

clear

## SETAR O JAVA HOME em .bashrc
echo $JAVA_HOME

#Apontar para o caminho onde estão os jars  estão assinados
JARPATH="/home/80621732915/git/signer/example/assinadorweb-example/resources/assinados"

for jarfile in $(ls $JARPATH/*-assinado.jar); do
    echo "verficando jar assinado para $jarfile"

    $JAVA_HOME/bin/jarsigner -verify -verbose -certs $jarfile

done

exit 0
