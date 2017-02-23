package org.demoiselle.signer.agent.desktop.web;

import java.security.Provider;
import java.security.Security;
import java.util.ServiceLoader;

import javax.security.auth.login.LoginException;

import org.demoiselle.signer.agent.desktop.Command;

import com.google.gson.Gson;

import sun.security.pkcs11.SunPKCS11;

public class Execute {

	public String executeCommand(Request request) {
		return this.executeCommand(request.toJson());
	}

	private void logout() {
		try {
			for (Provider provider : Security.getProviders())
				if (provider instanceof SunPKCS11)
					((SunPKCS11) provider).logout();
		} catch (LoginException e) {			
			e.printStackTrace();			
		}
	}

	public String executeCommand(String messageData) {
		
		// Always logout before run: This avoid the white hardware have communication problems
		logout();

		final Gson gson = new Gson();
		Request request = null;
		try {
			request = gson.fromJson(messageData, Request.class);
		} catch (Throwable error) {
			throw new InterpreterException(error);
		}
		if (request == null || request.getCommand() == null || request.getCommand().isEmpty())
			throw new RuntimeException("commando nao informado");

		ServiceLoader<Command> loader = ServiceLoader.load(Command.class);
		if (loader != null)
			for (Command commandLoaded : loader)
				if (commandLoaded.getCommandName().equalsIgnoreCase(request.getCommand()))
					return commandLoaded.doCommand(messageData);

		return "{\"error\" : \"comando nao localizado\"}";
	}

}
