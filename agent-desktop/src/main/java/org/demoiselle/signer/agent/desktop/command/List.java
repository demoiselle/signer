package org.demoiselle.signer.agent.desktop.command;

import java.util.ServiceLoader;

import org.demoiselle.signer.agent.desktop.Command;
import org.demoiselle.signer.agent.desktop.web.Request;

public class List extends AbstractCommand<Request, ListResponse> {

	public ListResponse doCommand(Request params) {
		ListResponse response = new ListResponse(params);
		ServiceLoader<Command> loader = ServiceLoader.load(Command.class);
		for (Command command : loader)
			response.addCommand(command.getCommandName());
		return response;
	}

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}
	
}
