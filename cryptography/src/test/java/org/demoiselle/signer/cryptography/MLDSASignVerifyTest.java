package org.demoiselle.signer.cryptography;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Integration tests that actually sign and verify data using ML-DSA (FIPS 204)
 * post-quantum algorithms via Bouncy Castle provider.
 * 
 * These tests prove the full sign/verify cycle works, not just enum registration.
 */
public class MLDSASignVerifyTest {

	private static final byte[] DATA = "Hello".getBytes();

	@BeforeClass
	public static void setup() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	@Test
	public void testSignAndVerify_ML_DSA_44() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
		KeyPair keyPair = kpg.generateKeyPair();
		assertNotNull("ML-DSA-44 key pair should be generated", keyPair);

		// Sign
		Signature signer = Signature.getInstance("ML-DSA-44", "BC");
		signer.initSign(keyPair.getPrivate());
		signer.update(DATA);
		byte[] signature = signer.sign();
		assertNotNull("Signature should not be null", signature);
		assertTrue("Signature should have content", signature.length > 0);

		// Verify
		Signature verifier = Signature.getInstance("ML-DSA-44", "BC");
		verifier.initVerify(keyPair.getPublic());
		verifier.update(DATA);
		assertTrue("Signature verification should succeed", verifier.verify(signature));
	}

	@Test
	public void testSignAndVerify_ML_DSA_65() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65", "BC");
		KeyPair keyPair = kpg.generateKeyPair();
		assertNotNull("ML-DSA-65 key pair should be generated", keyPair);

		Signature signer = Signature.getInstance("ML-DSA-65", "BC");
		signer.initSign(keyPair.getPrivate());
		signer.update(DATA);
		byte[] signature = signer.sign();
		assertNotNull("Signature should not be null", signature);

		Signature verifier = Signature.getInstance("ML-DSA-65", "BC");
		verifier.initVerify(keyPair.getPublic());
		verifier.update(DATA);
		assertTrue("Signature verification should succeed", verifier.verify(signature));
	}

	@Test
	public void testSignAndVerify_ML_DSA_87() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87", "BC");
		KeyPair keyPair = kpg.generateKeyPair();
		assertNotNull("ML-DSA-87 key pair should be generated", keyPair);

		Signature signer = Signature.getInstance("ML-DSA-87", "BC");
		signer.initSign(keyPair.getPrivate());
		signer.update(DATA);
		byte[] signature = signer.sign();
		assertNotNull("Signature should not be null", signature);

		Signature verifier = Signature.getInstance("ML-DSA-87", "BC");
		verifier.initVerify(keyPair.getPublic());
		verifier.update(DATA);
		assertTrue("Signature verification should succeed", verifier.verify(signature));
	}

	@Test
	public void testVerifyFailsWithWrongData() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
		KeyPair keyPair = kpg.generateKeyPair();

		Signature signer = Signature.getInstance("ML-DSA-44", "BC");
		signer.initSign(keyPair.getPrivate());
		signer.update(DATA);
		byte[] signature = signer.sign();

		// Verify with different data should fail
		Signature verifier = Signature.getInstance("ML-DSA-44", "BC");
		verifier.initVerify(keyPair.getPublic());
		verifier.update("Wrong".getBytes());
		assertTrue("Signature verification should FAIL with wrong data", !verifier.verify(signature));
	}

	@Test
	public void testVerifyFailsWithWrongKey() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", "BC");
		KeyPair keyPair1 = kpg.generateKeyPair();
		KeyPair keyPair2 = kpg.generateKeyPair();

		Signature signer = Signature.getInstance("ML-DSA-44", "BC");
		signer.initSign(keyPair1.getPrivate());
		signer.update(DATA);
		byte[] signature = signer.sign();

		// Verify with different public key should fail
		Signature verifier = Signature.getInstance("ML-DSA-44", "BC");
		verifier.initVerify(keyPair2.getPublic());
		verifier.update(DATA);
		assertTrue("Signature verification should FAIL with wrong key", !verifier.verify(signature));
	}
}
