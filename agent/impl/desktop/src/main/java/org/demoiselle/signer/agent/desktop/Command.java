package org.demoiselle.signer.agent.desktop;

public interface Command {
	
	public String getCommandName();
	public String doCommand(String params);

}
