package org.demoiselle.signer.cryptography;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * Tests for AsymmetricAlgorithmEnum, including ML-DSA post-quantum support.
 */
public class AsymmetricAlgorithmEnumTest {

	@Test
	public void testML_DSA_exists() {
		AsymmetricAlgorithmEnum alg = AsymmetricAlgorithmEnum.ML_DSA;
		assertNotNull("ML_DSA should exist in AsymmetricAlgorithmEnum", alg);
		assertEquals("ML-DSA", alg.getAlgorithm());
	}

	@Test
	public void testML_DSA_resolveByName() {
		AsymmetricAlgorithmEnum alg = AsymmetricAlgorithmEnum.getAsymmetricAlgorithmEnum("ML-DSA");
		assertNotNull("Should resolve ML-DSA by algorithm name", alg);
		assertEquals(AsymmetricAlgorithmEnum.ML_DSA, alg);
	}

	@Test
	public void testML_DSA_caseInsensitive() {
		AsymmetricAlgorithmEnum alg = AsymmetricAlgorithmEnum.getAsymmetricAlgorithmEnum("ml-dsa");
		assertNotNull("ML-DSA resolution should be case insensitive", alg);
		assertEquals(AsymmetricAlgorithmEnum.ML_DSA, alg);
	}

	// Regression: existing algorithms still work
	@Test
	public void testRSA_exists() {
		AsymmetricAlgorithmEnum alg = AsymmetricAlgorithmEnum.getAsymmetricAlgorithmEnum("RSA/ECB/PKCS1Padding");
		assertNotNull("RSA should still resolve", alg);
		assertEquals(AsymmetricAlgorithmEnum.RSA, alg);
	}

	@Test
	public void testECDSA_exists() {
		AsymmetricAlgorithmEnum alg = AsymmetricAlgorithmEnum.getAsymmetricAlgorithmEnum("ECDSA");
		assertNotNull("ECDSA should still resolve", alg);
		assertEquals(AsymmetricAlgorithmEnum.ECDSA, alg);
	}

	@Test
	public void testDefaultIsRSA() {
		assertEquals(AsymmetricAlgorithmEnum.RSA, AsymmetricAlgorithmEnum.DEFAULT);
	}

	@Test
	public void testUnknownAlgorithm_returnsNull() {
		AsymmetricAlgorithmEnum alg = AsymmetricAlgorithmEnum.getAsymmetricAlgorithmEnum("UNKNOWN");
		assertNull("Unknown algorithm should return null", alg);
	}
}
