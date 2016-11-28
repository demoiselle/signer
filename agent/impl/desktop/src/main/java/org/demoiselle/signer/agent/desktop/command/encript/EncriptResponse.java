package org.demoiselle.signer.agent.desktop.command.encript;

import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.web.Response;

public class EncriptResponse extends Response {
	
	private String encripted;
	private Certificate by;
	private String publicKey;
	
	public String getEncripted() {
		return encripted;
	}
	public void setEncripted(String encripted) {
		this.encripted = encripted;
	}
	public Certificate getBy() {
		return by;
	}
	public void setBy(Certificate by) {
		this.by = by;
	}
	public String getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	
	
}
