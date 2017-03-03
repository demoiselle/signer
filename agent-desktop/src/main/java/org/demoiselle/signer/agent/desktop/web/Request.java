package org.demoiselle.signer.agent.desktop.web;

import com.google.gson.Gson;

public class Request {
	
	private String command;
	private long requestId;
	
	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
	}

	public long getRequestId() {
		return requestId;
	}

	public void setRequestId(long id) {
		this.requestId = id;
	}
	
	public String toJson() {
		return (new Gson()).toJson(this);
	}
	
}