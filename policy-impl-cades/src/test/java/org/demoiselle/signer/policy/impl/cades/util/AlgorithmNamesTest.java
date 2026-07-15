package org.demoiselle.signer.policy.impl.cades.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

/**
 * Tests for AlgorithmNames enum, focusing on ML-DSA (FIPS 204) post-quantum algorithm support.
 */
public class AlgorithmNamesTest {

	// ML-DSA OIDs (NIST FIPS 204)
	private static final String OID_ML_DSA_44 = "2.16.840.1.101.3.4.3.17";
	private static final String OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18";
	private static final String OID_ML_DSA_87 = "2.16.840.1.101.3.4.3.19";

	@Test
	public void testGetAlgorithmNameByOID_ML_DSA_44() {
		String name = AlgorithmNames.getAlgorithmNameByOID(OID_ML_DSA_44);
		assertNotNull("ML-DSA-44 algorithm name should not be null", name);
		assertEquals("ML-DSA-44", name);
	}

	@Test
	public void testGetAlgorithmNameByOID_ML_DSA_65() {
		String name = AlgorithmNames.getAlgorithmNameByOID(OID_ML_DSA_65);
		assertNotNull("ML-DSA-65 algorithm name should not be null", name);
		assertEquals("ML-DSA-65", name);
	}

	@Test
	public void testGetAlgorithmNameByOID_ML_DSA_87() {
		String name = AlgorithmNames.getAlgorithmNameByOID(OID_ML_DSA_87);
		assertNotNull("ML-DSA-87 algorithm name should not be null", name);
		assertEquals("ML-DSA-87", name);
	}

	@Test
	public void testGetOIDByAlgorithmName_ML_DSA_44() {
		String oid = AlgorithmNames.getOIDByAlgorithmName("ML-DSA-44");
		assertNotNull("ML-DSA-44 OID should not be null", oid);
		assertEquals(OID_ML_DSA_44, oid);
	}

	@Test
	public void testGetOIDByAlgorithmName_ML_DSA_65() {
		String oid = AlgorithmNames.getOIDByAlgorithmName("ML-DSA-65");
		assertNotNull("ML-DSA-65 OID should not be null", oid);
		assertEquals(OID_ML_DSA_65, oid);
	}

	@Test
	public void testGetOIDByAlgorithmName_ML_DSA_87() {
		String oid = AlgorithmNames.getOIDByAlgorithmName("ML-DSA-87");
		assertNotNull("ML-DSA-87 OID should not be null", oid);
		assertEquals(OID_ML_DSA_87, oid);
	}

	@Test
	public void testRoundTrip_ML_DSA_44() {
		String name = AlgorithmNames.getAlgorithmNameByOID(OID_ML_DSA_44);
		String oid = AlgorithmNames.getOIDByAlgorithmName(name);
		assertEquals("Round-trip OID -> Name -> OID should return original OID", OID_ML_DSA_44, oid);
	}

	@Test
	public void testRoundTrip_ML_DSA_65() {
		String name = AlgorithmNames.getAlgorithmNameByOID(OID_ML_DSA_65);
		String oid = AlgorithmNames.getOIDByAlgorithmName(name);
		assertEquals("Round-trip OID -> Name -> OID should return original OID", OID_ML_DSA_65, oid);
	}

	@Test
	public void testRoundTrip_ML_DSA_87() {
		String name = AlgorithmNames.getAlgorithmNameByOID(OID_ML_DSA_87);
		String oid = AlgorithmNames.getOIDByAlgorithmName(name);
		assertEquals("Round-trip OID -> Name -> OID should return original OID", OID_ML_DSA_87, oid);
	}

	// Verify existing algorithms still work correctly
	@Test
	public void testExistingAlgorithm_SHA256withRSA() {
		assertEquals("SHA256withRSA", AlgorithmNames.getAlgorithmNameByOID("1.2.840.113549.1.1.11"));
		assertEquals("1.2.840.113549.1.1.11", AlgorithmNames.getOIDByAlgorithmName("SHA256withRSA"));
	}

	@Test
	public void testExistingAlgorithm_SHA512withRSA() {
		assertEquals("SHA512withRSA", AlgorithmNames.getAlgorithmNameByOID("1.2.840.113549.1.1.13"));
		assertEquals("1.2.840.113549.1.1.13", AlgorithmNames.getOIDByAlgorithmName("SHA512withRSA"));
	}

	@Test
	public void testExistingAlgorithm_SHA256() {
		assertEquals("SHA256", AlgorithmNames.getAlgorithmNameByOID("2.16.840.1.101.3.4.2.1"));
		assertEquals("2.16.840.1.101.3.4.2.1", AlgorithmNames.getOIDByAlgorithmName("SHA256"));
	}
}
