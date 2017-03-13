package org.demoiselle.signer.agent.desktop.web;

import com.google.gson.Gson;

public class Response {

	private String command;
	private long requestId;
	private boolean actionCanceled = false;

	public Response() {
	}

	public Response(Request request) {
		this.command = request != null ? request.getCommand() : "";
		this.requestId = request != null ? request.getRequestId() : 0;
	}

	public String getCommand() {
		return command;
	}

	public void setCommand(String command) {
		this.command = command;
	}

	public long getRequestId() {
		return requestId;
	}

	public void setRequestId(long requestId) {
		this.requestId = requestId;
	}

	public boolean getActionCanceled() {
		return actionCanceled;
	}

	public void setActionCanceled(boolean canceled) {
		actionCanceled = canceled;
	}

	public String toJson() {
		return (new Gson()).toJson(this);
	}

}
