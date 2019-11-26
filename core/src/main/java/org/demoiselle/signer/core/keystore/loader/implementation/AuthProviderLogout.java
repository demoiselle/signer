package org.demoiselle.signer.core.keystore.loader.implementation;

import java.security.AuthProvider;
import java.security.Provider;
import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthProviderLogout {

	private static final Logger logger = LoggerFactory.getLogger(AuthProviderLogout.class);
	
	public boolean doLogout(){
		try {
			for (Provider provider : Security.getProviders())
				if (provider instanceof AuthProvider)
					((AuthProvider)provider).logout();
			return true;
		} catch (Throwable error) {
			logger.error(error.getMessage());
			return false;
		}
	}
	

}
