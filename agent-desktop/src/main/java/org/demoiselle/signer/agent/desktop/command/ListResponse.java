package org.demoiselle.signer.agent.desktop.command;

import java.util.ArrayList;

import org.demoiselle.signer.agent.desktop.web.Request;
import org.demoiselle.signer.agent.desktop.web.Response;

public class ListResponse extends Response {
	
	private ArrayList<String> commands;
	
	public ListResponse() {
		super.setCommand("list");
	}
	
	public ListResponse(Request request) {
		super(request);
	}

	public ArrayList<String> getCommands() {
		return commands;
	}

	public void setCommands(ArrayList<String> commands) {
		this.commands = commands;
	}
	
	public void addCommand(String command) {
		if (this.commands == null)
			this.commands = new ArrayList<String>();
		this.commands.add(command);
	}

}
