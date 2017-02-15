package org.demoiselle.signer.agent.desktop.web;

import com.google.gson.Gson;

public class Request {
	
	private String command;
	private Integer id;

	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}
	
	public String toJson() {
		return (new Gson()).toJson(this);
	}
	
}