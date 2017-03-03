package org.demoiselle.signer.agent.desktop.command;

import org.demoiselle.signer.agent.desktop.web.Request;
import org.demoiselle.signer.agent.desktop.web.Response;

public class StatusResponse extends Response {
	
	private String status;
	
	public StatusResponse() {
		super.setCommand("status");
	}
	
	public StatusResponse(Request request) {
		super(request);
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

}
