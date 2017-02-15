package org.demoiselle.signer.agent.desktop.command.cert;

import org.demoiselle.signer.agent.desktop.web.Request;

public class ListCertsRequest extends Request {
	
	public ListCertsRequest() {
		super.setCommand("listcerts");
	}
}
