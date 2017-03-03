package org.demoiselle.signer.agent.desktop.web;

import java.util.ServiceLoader;

import org.demoiselle.signer.agent.desktop.Command;
import org.demoiselle.signer.agent.desktop.command.cert.LogoutPKCS11;

import com.google.gson.Gson;

public class Execute {

	public String executeCommand(Request request) {
		return this.executeCommand(request.toJson());
	}

	public String executeCommand(String messageData) {
		
		// Always logout before run: This avoid the white hardware have communication problems
		(new LogoutPKCS11()).doCommand((String)null);

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
