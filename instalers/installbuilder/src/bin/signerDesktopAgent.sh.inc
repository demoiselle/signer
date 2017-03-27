#!/bin/sh

##############################################################################
##                                                                          ##
##  Demoiselle Signer Destktop Bootstrap for UN*X                           ##
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

if type -p java; then
    _java=java
elif [[ -n "$JAVA_HOME" ]] && [[ -x "$JAVA_HOME/bin/java" ]];  then
    _java="$JAVA_HOME/bin/java"
else
    echo "no java" > log1.txt
    exit
fi

if [[ "$_java" ]]; then
    version=$("$_java" -version 2>&1 | awk -F '"' '/version/ {print $2}')
    echo version "$version"
    if [[ "$version" < "1.7" ]]; then
        echo version is less than 1.7 > log2.txt
        exit
    fi
fi

# Setup SIGNER_DESKTOP_HOME
if [ "x$SIGNER_DESKTOP_HOME" = "x" ];
then
    # get the full path (without any relative bits)
    SIGNER_DESKTOP_HOME=`cd $DIRNAME; pwd`
fi
SIGNER_DESKTOP_HOME=$SIGNER_DESKTOP_HOME/lib
export SIGNER_DESKTOP_HOME

echo $SIGNER_DESKTOP_HOME > log3.txt

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

echo "executar" > log4.txt

java $JAVA_OPTS -jar $SIGNER_DESKTOP_HOME/agent-desktop-3.0.0-SNAPSHOT.jar 
