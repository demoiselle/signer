package org.demoiselle.signer.agent.desktop.command;

import org.demoiselle.signer.agent.desktop.Command;

public class Status implements Command {

	public String doCommand(String params) {
		return "{ \"status:\" : \"OK\" }";
	}
	
	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}
	

}
