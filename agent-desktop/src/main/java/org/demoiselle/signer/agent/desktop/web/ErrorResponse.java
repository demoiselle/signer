package org.demoiselle.signer.agent.desktop.web;

public class ErrorResponse extends Response {
	
	public ErrorResponse () {
		super();
	}

	public ErrorResponse (Request request) {
		super(request);
	}
	
	public ErrorResponse (Request request, String error) {
		super(request);
		this.error = error;
	}
	
	public ErrorResponse (Request request, Throwable error) {
		super(request);
		this.error = error != null ? error.getMessage() : null;
		this.causedBy = error.getCause() != null ? error.getCause().getMessage() : null;
	}

	private String error;
	private String causedBy;

	public String getCausedBy() {
		return causedBy;
	}

	public void setCausedBy(String causedBy) {
		this.causedBy = causedBy;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}
	

}
