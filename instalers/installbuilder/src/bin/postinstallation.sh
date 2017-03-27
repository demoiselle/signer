#!/bin/bash

# The target installation directory ${installdir} is passed as the first
# argument to the script. This script in turns creates a demo.sh script
# and substitutes the @@installdir@@ placefolder with the actual
# installation directory value

sed "s:@@installdir@@:$1:g" $1/bin/signerDesktopAgent.sh.inc > $1/bin/signerDesktopAgent.sh
chmod +rx $1/bin/signerDesktopAgent.sh
rm -f $1/bin/signerDesktopAgent.sh.inc
cp ${HOME}/Desktop/Demoiselle\ Signer\ Agent.desktop ${HOME}/.config/autostart/DemoiselleSignerAgent.desktop
rm -f $1/bin/postinstallation.sh
rm -f $1/DemoiselleSignerAgent-launcher.run

