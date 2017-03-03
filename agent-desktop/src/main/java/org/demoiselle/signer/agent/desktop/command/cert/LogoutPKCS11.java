package org.demoiselle.signer.agent.desktop.command.cert;

import java.security.Provider;
import java.security.Security;

import org.demoiselle.signer.agent.desktop.command.AbstractCommand;
import org.demoiselle.signer.agent.desktop.web.Request;
import org.demoiselle.signer.agent.desktop.web.Response;

import sun.security.pkcs11.SunPKCS11;

public class LogoutPKCS11 extends AbstractCommand<Request, Response>{

	@Override
	public Response doCommand(Request request) {
		try {
			for (Provider provider : Security.getProviders())
				if (provider instanceof SunPKCS11)
					((SunPKCS11)provider).logout();
		} catch (Throwable error) {
		}
		return new Response(request);
	}

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}

}
