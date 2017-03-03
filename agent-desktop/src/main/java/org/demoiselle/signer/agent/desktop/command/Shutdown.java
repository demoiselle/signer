package org.demoiselle.signer.agent.desktop.command;

import org.demoiselle.signer.agent.desktop.web.Request;
import org.demoiselle.signer.agent.desktop.web.Response;

public class Shutdown  extends AbstractCommand<Request, Response> {

	public String getCommandName() {
		return this.getClass().getSimpleName().toLowerCase();
	}

	@Override
	public Response doCommand(Request request) {
		System.exit(0);
		return null;
	}
	

}
