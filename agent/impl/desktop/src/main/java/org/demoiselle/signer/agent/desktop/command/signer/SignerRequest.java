package org.demoiselle.signer.agent.desktop.command.signer;

import org.demoiselle.signer.agent.desktop.web.Request;

public class SignerRequest extends Request {
	
	/*
	 * raw
	 * hash 
	 */
	private String type = "raw";
	/*
	 * base64
	 * hexa
	 * text
	 */
	private String format = "text";
	private Boolean compacted = false;
	private String alias;
	private String signaturePolicy = "AD_RB_CADES_2_2";
	private String provider;
	private String content;
	
	public SignerRequest() {
		super.setCommand("signer");
	}

	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getFormat() {
		return format;
	}
	public void setFormat(String format) {
		this.format = format;
	}
	public Boolean getCompacted() {
		return compacted;
	}
	public void setCompacted(Boolean compacted) {
		this.compacted = compacted;
	}
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}
	public String getAlias() {
		return alias;
	}
	public void setAlias(String alias) {
		this.alias = alias;
	}
	public String getProvider() {
		return provider;
	}
	public void setProvider(String provider) {
		this.provider = provider;
	}
	public String getSignaturePolicy() {
		return signaturePolicy;
	}
	public void setSignaturePolicy(String signaturePolicy) {
		this.signaturePolicy = signaturePolicy;
	}
	

}
