package org.demoiselle.signer.agent.desktop.command;

import org.demoiselle.signer.agent.desktop.web.Request;

public class Status extends AbstractCommand<Request, StatusResponse> {

	@Override
	public StatusResponse doCommand(Request request) {
		StatusResponse response = new StatusResponse(request);
		response.setStatus("OK");
		return response;
	}
	
	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}
	
}
