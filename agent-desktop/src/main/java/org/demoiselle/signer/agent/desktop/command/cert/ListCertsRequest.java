package org.demoiselle.signer.agent.desktop.command.cert;

import org.demoiselle.signer.agent.desktop.web.Request;

public class ListCertsRequest extends Request {

	private boolean useForSignature = false;

	public ListCertsRequest() {
		super.setCommand("listcerts");
	}

	public boolean isUseForSignature() {
		return useForSignature;
	}

	public void setUseForSignature(boolean useForSignature) {
		this.useForSignature = useForSignature;
	}

}
