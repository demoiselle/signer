package org.demoiselle.signer.policy.impl.cades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * Tests for SignerAlgorithmEnum, focusing on ML-DSA (FIPS 204) post-quantum algorithm support.
 */
public class SignerAlgorithmEnumTest {

	// ML-DSA OIDs (NIST FIPS 204)
	private static final String OID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
	private static final String OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
	private static final String OID_ML_DSA_87 = "2.16.840.1.101.3.4.3.19";

	// --- ML-DSA-44 Tests ---

	@Test
	public void testML_DSA_44_existsInEnum() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.ML_DSA_44;
		assertNotNull(alg);
		assertEquals("ML-DSA-44", alg.getAlgorithm());
		assertEquals("ML-DSA", alg.getAlgorithmCipher());
		assertEquals(OID_ML_DSA_44, alg.getOIDAlgorithmCipher());
	}

	@Test
	public void testML_DSA_44_hashAlgorithm() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.ML_DSA_44;
		assertEquals("SHA-256", alg.getAlgorithmHash());
		assertEquals("2.16.840.1.101.3.4.2.1", alg.getOIDAlgorithmHash());
	}

	@Test
	public void testML_DSA_44_resolveByName() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerAlgorithmEnum("ML-DSA-44");
		assertNotNull("Should resolve ML-DSA-44 by name", alg);
		assertEquals(SignerAlgorithmEnum.ML_DSA_44, alg);
	}

	@Test
	public void testML_DSA_44_resolveByHashOID() {
		// ML-DSA-44 uses SHA-256 hash OID (shared with SHA256withRSA/ECDSA)
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerOIDAlgorithmHashEnum("2.16.840.1.101.3.4.2.1");
		assertNotNull("Should resolve by SHA-256 hash OID", alg);
	}

	@Test
	public void testML_DSA_44_resolveByCipherOID() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerOIDAlgorithmCipherEnum(OID_ML_DSA_44);
		assertNotNull("Should resolve ML-DSA-44 by cipher OID", alg);
		assertEquals(SignerAlgorithmEnum.ML_DSA_44, alg);
	}

	// --- ML-DSA-65 Tests ---

	@Test
	public void testML_DSA_65_existsInEnum() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.ML_DSA_65;
		assertNotNull(alg);
		assertEquals("ML-DSA-65", alg.getAlgorithm());
		assertEquals("ML-DSA", alg.getAlgorithmCipher());
		assertEquals(OID_ML_DSA_65, alg.getOIDAlgorithmCipher());
	}

	@Test
	public void testML_DSA_65_resolveByCipherOID() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerOIDAlgorithmCipherEnum(OID_ML_DSA_65);
		assertNotNull("Should resolve ML-DSA-65 by cipher OID", alg);
		assertEquals(SignerAlgorithmEnum.ML_DSA_65, alg);
	}

	// --- ML-DSA-87 Tests ---

	@Test
	public void testML_DSA_87_existsInEnum() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.ML_DSA_87;
		assertNotNull(alg);
		assertEquals("ML-DSA-87", alg.getAlgorithm());
		assertEquals("ML-DSA", alg.getAlgorithmCipher());
		assertEquals(OID_ML_DSA_87, alg.getOIDAlgorithmCipher());
	}

	@Test
	public void testML_DSA_87_hashAlgorithm() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.ML_DSA_87;
		assertEquals("SHA-512", alg.getAlgorithmHash());
		assertEquals("2.16.840.1.101.3.4.2.3", alg.getOIDAlgorithmHash());
	}

	@Test
	public void testML_DSA_87_resolveByCipherOID() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerOIDAlgorithmCipherEnum(OID_ML_DSA_87);
		assertNotNull("Should resolve ML-DSA-87 by cipher OID", alg);
		assertEquals(SignerAlgorithmEnum.ML_DSA_87, alg);
	}

	// --- Negative / edge-case tests ---

	@Test
	public void testUnknownOID_returnsNull() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerOIDAlgorithmCipherEnum("9.9.9.9.9");
		assertNull("Unknown OID should return null", alg);
	}

	@Test
	public void testUnknownName_returnsNull() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerAlgorithmEnum("UnknownAlgorithm");
		assertNull("Unknown algorithm name should return null", alg);
	}

	// --- Existing algorithms regression ---

	@Test
	public void testExisting_SHA256withRSA() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerAlgorithmEnum("SHA256withRSA");
		assertNotNull(alg);
		assertEquals("RSA", alg.getAlgorithmCipher());
		assertEquals("SHA-256", alg.getAlgorithmHash());
	}

	@Test
	public void testExisting_SHA512withECDSA() {
		SignerAlgorithmEnum alg = SignerAlgorithmEnum.getSignerAlgorithmEnum("SHA512withECDSA");
		assertNotNull(alg);
		assertEquals("ECDSA", alg.getAlgorithmCipher());
		assertEquals("SHA-512", alg.getAlgorithmHash());
	}

	@Test
	public void testDefaultAlgorithm() {
		assertEquals(SignerAlgorithmEnum.SHA512withRSA, SignerAlgorithmEnum.DEFAULT);
	}
}
