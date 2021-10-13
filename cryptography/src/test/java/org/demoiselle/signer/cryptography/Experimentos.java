package org.demoiselle.signer.cryptography;

import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import static junit.framework.TestCase.assertEquals;

public class Experimentos {

	@Test
	public void defaultProvider() throws NoSuchAlgorithmException {
		MessageDigest digest = MessageDigest.getInstance("MD5");
		Provider provider = digest.getProvider();
		assertEquals("SUN", provider.getName());
	}
}
