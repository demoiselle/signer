package org.demoiselle.signer.agent.desktop.command.cert;

import java.security.Provider;
import java.security.Security;

import org.demoiselle.signer.agent.desktop.Command;

import sun.security.pkcs11.SunPKCS11;

public class LogoutPKCS11 implements Command {

	public String doCommand(String params) {
		try {
			for (Provider provider : Security.getProviders())
				if (provider instanceof SunPKCS11)
					((SunPKCS11)provider).logout();
		} catch (Throwable error) {
		}
		return "{}";
	}

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}

}
