package org.demoiselle.signer.agent.desktop.web;

import com.google.gson.Gson;

public class Response {
	
	private String command;
	private Integer requestId;
	
	public Response() {
	}
	
	public Response(Request request) {
		this.command = request!= null ? request.getCommand() : "";
		this.requestId = request != null ? request.getRequestId() : 0;
	}
	
	public String getCommand() {
		return command;
	}
	public void setCommand(String command) {
		this.command = command;
	}
	public Integer getRequestId() {
		return requestId;
	}
	public void setRequestId(Integer requestId) {
		this.requestId = requestId;
	}	
	public String toJson() {
		return (new Gson()).toJson(this);
	}

}
