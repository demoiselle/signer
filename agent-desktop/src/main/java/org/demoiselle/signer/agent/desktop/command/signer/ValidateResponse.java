package org.demoiselle.signer.agent.desktop.command.signer;

import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.web.Response;

public class ValidateResponse extends Response {
	
	private boolean valid;
	private Certificate by;
	private String message;
	private String causedBy;
	
	public boolean isValid() {
		return valid;
	}
	public void setValid(boolean valid) {
		this.valid = valid;
	}
	public Certificate getBy() {
		return by;
	}
	public void setBy(Certificate by) {
		this.by = by;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public String getCausedBy() {
		return causedBy;
	}
	public void setCausedBy(String causedBy) {
		this.causedBy = causedBy;
	}
}
