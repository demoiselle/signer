package org.demoiselle.signer.cryptography;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class DigestAlgorithmEnumTest {

	@Test
	public void testDefaultIsSHA256() {
		assertEquals(DigestAlgorithmEnum.SHA_256, DigestAlgorithmEnum.DEFAULT);
	}

	@Test
	public void testGetAlgorithmName() {
		assertEquals("SHA-256", DigestAlgorithmEnum.SHA_256.getAlgorithm());
		assertEquals("SHA-1", DigestAlgorithmEnum.SHA_1.getAlgorithm());
		assertEquals("SHA-512", DigestAlgorithmEnum.SHA_512.getAlgorithm());
		assertEquals("MD5", DigestAlgorithmEnum.MD5.getAlgorithm());
	}

	@Test
	public void testResolveByName_SHA256() {
		DigestAlgorithmEnum alg = DigestAlgorithmEnum.getDigestAlgorithmEnum("SHA-256");
		assertNotNull(alg);
		assertEquals(DigestAlgorithmEnum.SHA_256, alg);
	}

	@Test
	public void testResolveByName_caseInsensitive() {
		DigestAlgorithmEnum alg = DigestAlgorithmEnum.getDigestAlgorithmEnum("sha-256");
		assertNotNull(alg);
		assertEquals(DigestAlgorithmEnum.SHA_256, alg);
	}

	@Test
	public void testResolveByName_SHA512() {
		DigestAlgorithmEnum alg = DigestAlgorithmEnum.getDigestAlgorithmEnum("SHA-512");
		assertNotNull(alg);
		assertEquals(DigestAlgorithmEnum.SHA_512, alg);
	}

	@Test
	public void testResolveByName_MD5() {
		DigestAlgorithmEnum alg = DigestAlgorithmEnum.getDigestAlgorithmEnum("MD5");
		assertNotNull(alg);
		assertEquals(DigestAlgorithmEnum.MD5, alg);
	}

	@Test
	public void testResolveByName_SHA3_256() {
		DigestAlgorithmEnum alg = DigestAlgorithmEnum.getDigestAlgorithmEnum("SHA3-256");
		assertNotNull(alg);
		assertEquals(DigestAlgorithmEnum.SHA3_256, alg);
	}

	@Test
	public void testUnknownAlgorithm_returnsNull() {
		assertNull(DigestAlgorithmEnum.getDigestAlgorithmEnum("UNKNOWN-ALGO"));
	}

	@Test
	public void testAllEnumValues_haveNonNullAlgorithm() {
		for (DigestAlgorithmEnum value : DigestAlgorithmEnum.values()) {
			assertNotNull("Algorithm name should not be null for " + value.name(), value.getAlgorithm());
		}
	}
}
