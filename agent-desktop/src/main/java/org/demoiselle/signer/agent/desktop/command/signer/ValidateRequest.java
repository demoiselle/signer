package org.demoiselle.signer.agent.desktop.command.signer;

import org.demoiselle.signer.agent.desktop.web.Request;

public class ValidateRequest extends Request {
	
	private String content;
	private String signature;
	private String format;
	
	public ValidateRequest() {
		this.setCommand("validate");
	}
	
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	public String getFormat() {
		return format;
	}
	public void setFormat(String format) {
		this.format = format;
	}

}