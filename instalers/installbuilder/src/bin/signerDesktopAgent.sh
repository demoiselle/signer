#!/bin/bash

##############################################################################
##                                                                          ##
##  Demoiselle Signer Destktop Bootstrap for MAC                            ##
##                                                                          ##
##############################################################################

### $Id$ ###

DIRNAME=`dirname $0`

# OS specific support (must be 'true' or 'false').
cygwin=false;
darwin=false;
case "`uname`" in
    CYGWIN*)
        cygwin=true
        ;;
    Darwin*)
        darwin=true
        ;;
esac

# Setup SIGNER_DESKTOP_HOME
if [ "x$SIGNER_DESKTOP_HOME" = "x" ];
then
    # get the full path (without any relative bits)
    SIGNER_DESKTOP_HOME=`cd $DIRNAME; pwd`
fi

export SIGNER_DESKTOP_HOME

echo $SIGNER_DESKTOP_HOME 

SIGNER_JAVA_HOME=`cd $SIGNER_DESKTOP_HOME/../java/; pwd`
export SIGNER_JAVA_HOME

echo $SIGNER_JAVA_HOME


if [ -f "$SIGNER_JAVA_HOME/bin/java" ]
then
  JAVA=$SIGNER_JAVA_HOME/bin/java
else
   echo "Não encontrou java"
    exit
fi



JAVA_OPTS="-Xms128m -Xmx1024m -XX:MinHeapFreeRatio=20 -XX:MaxHeapFreeRatio=40"

if $darwin
then
    JAVA_OPTS="$JAVA_OPTS -Dswing.crossplatformlaf=apple.laf.AquaLookAndFeel -Dapple.eawt.quitStrategy=CLOSE_ALL_WINDOWS"
fi

if [ $SIGNER_DESKTOP_HOME != "" ] 
then
    JAVA_OPTS="$JAVA_OPTS -Djava.library.path=$SIGNER_DESKTOP_HOME"
fi

export JAVA_OPTS

# For Cygwin, switch paths to Windows format before running java
if [ $cygwin = "true" ] 
then
    SIGNER_DESKTOP_HOME=`cygpath --path --dos "$SIGNER_DESKTOP_HOME"`
fi

cd $DIRNAME

echo "executar" > log3.txt

$JAVA $JAVA_OPTS -jar $SIGNER_DESKTOP_HOME/lib/agent-desktop-3.0.0-SNAPSHOT.jar 
