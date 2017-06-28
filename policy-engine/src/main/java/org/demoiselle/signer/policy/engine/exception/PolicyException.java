package org.demoiselle.signer.policy.engine.exception;
/**
 * custom unchecked exceptions for package   
 */
public class PolicyException extends RuntimeException {

	private static final long serialVersionUID = 1L;
	

	public PolicyException() {
		super();
	}

	public PolicyException(String message, Throwable cause,
			boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public PolicyException(String message, Throwable cause) {
		super(message, cause);
	}

	public PolicyException(String message) {
		super(message);
	}

	public PolicyException(Throwable cause) {
		super(cause);
	}

	

}
