package org.demoiselle.signer.agent.desktop.command.cert;

public class Certificate {
	
	private String alias;
	private String provider;
	private String subject;
	private String notBefore;
	private String notAfter;
	private String serial;
	
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public String getNotBefore() {
		return notBefore;
	}
	public void setNotBefore(String notBefore) {
		this.notBefore = notBefore;
	}
	public String getNotAfter() {
		return notAfter;
	}
	public void setNotAfter(String notAfter) {
		this.notAfter = notAfter;
	}
	public String getSerial() {
		return serial;
	}
	public void setSerial(String serial) {
		this.serial = serial;
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

}
