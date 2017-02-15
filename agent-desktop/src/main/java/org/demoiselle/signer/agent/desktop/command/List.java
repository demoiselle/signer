package org.demoiselle.signer.agent.desktop.command;

import java.util.ServiceLoader;

import org.demoiselle.signer.agent.desktop.Command;

public class List implements Command {

	public String doCommand(String params) {
		StringBuilder builder = new StringBuilder();
		builder.append("{ \"commands\": [");
		ServiceLoader<Command> loader = ServiceLoader.load(Command.class);
		for (Command command : loader)
			builder.append("\"" + command.getCommandName() + "\", ");
		builder.append("\"\"]} ");
		return builder.toString().replaceAll(", \"\"", "");
	}

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}

}
