package org.demoiselle.signer.agent.desktop.web;

import com.google.gson.Gson;

public class Request {
	
	private String command;
	private Integer requestId;
	
	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
	}

	public Integer getRequestId() {
		return requestId;
	}

	public void setRequestId(Integer id) {
		this.requestId = id;
	}
	
	public String toJson() {
		return (new Gson()).toJson(this);
	}
	
}