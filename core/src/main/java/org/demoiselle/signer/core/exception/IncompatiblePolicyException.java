package org.demoiselle.signer.core.exception;

public class IncompatiblePolicyException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public IncompatiblePolicyException(String message) {
		super(message);
	}

	public IncompatiblePolicyException(String message, Throwable cause) {
		super(message, cause);
	}
}
