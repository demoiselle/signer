package org.demoiselle.signer.core.keystore.loader.implementation;

import java.security.Provider;
import java.security.Security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.pkcs11.SunPKCS11;

@SuppressWarnings("restriction")
public class PKCS11Logout {

	private static final Logger logger = LoggerFactory.getLogger(PKCS11Logout.class);
	
	public boolean doLogout(){
		try {
			for (Provider provider : Security.getProviders())
				if (provider instanceof SunPKCS11)
					((SunPKCS11) provider).logout();
			return true;
		} catch (Throwable error) {
			logger.error(error.getMessage());
			return false;
		}
	}
	

}
