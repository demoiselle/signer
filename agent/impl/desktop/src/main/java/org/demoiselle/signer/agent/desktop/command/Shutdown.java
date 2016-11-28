package org.demoiselle.signer.agent.desktop.command;

import org.demoiselle.signer.agent.desktop.Command;

public class Shutdown implements Command {

	public String doCommand(String params) {
		System.exit(0);
		return null;
	}

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}
	

}
