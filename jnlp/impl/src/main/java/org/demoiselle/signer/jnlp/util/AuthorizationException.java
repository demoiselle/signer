package org.demoiselle.signer.jnlp.util;

public class AuthorizationException extends RuntimeException{
	private static final long serialVersionUID = 1L;


	/**
	 * Construtor recebendo mensagem e causa
	 * 
	 * @param message
	 * @param error
	 */
	public AuthorizationException(String message, Throwable error) {
		super(message, error);
	}

	
	/**
	 * Construtor recebendo mensagem
	 * 
	 * @param message
	 */
	public AuthorizationException(String message) {
		super(message);
	}


}
