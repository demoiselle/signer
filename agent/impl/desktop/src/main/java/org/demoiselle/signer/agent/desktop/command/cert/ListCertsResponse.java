package org.demoiselle.signer.agent.desktop.command.cert;

import java.util.Collection;

import org.demoiselle.signer.agent.desktop.web.Response;

public class ListCertsResponse extends Response {
	
	private Collection<Certificate> certificates;
	
	public ListCertsResponse() {
		super.setCommand("listcerts");
	}

	public Collection<Certificate> getCertificates() {
		return certificates;
	}

	public void setCertificates(Collection<Certificate> certificates) {
		this.certificates = certificates;
	}
	
}
