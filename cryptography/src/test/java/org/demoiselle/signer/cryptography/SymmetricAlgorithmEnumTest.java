package org.demoiselle.signer.cryptography;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public class SymmetricAlgorithmEnumTest {

	@Test
	public void testDefaultIsAES() {
		assertEquals(SymmetricAlgorithmEnum.AES, SymmetricAlgorithmEnum.DEFAULT);
	}

	@Test
	public void testAES_properties() {
		SymmetricAlgorithmEnum aes = SymmetricAlgorithmEnum.AES;
		assertEquals("AES/ECB/PKCS5Padding", aes.getAlgorithm());
		assertEquals("AES", aes.getKeyAlgorithm());
		assertEquals(128, aes.getSize());
	}

	@Test
	public void testTripleDES_properties() {
		SymmetricAlgorithmEnum des = SymmetricAlgorithmEnum.TRI_DES;
		assertEquals("DESede/ECB/PKCS5Padding", des.getAlgorithm());
		assertEquals("DESede", des.getKeyAlgorithm());
		assertEquals(112, des.getSize());
	}

	@Test
	public void testResolveByAlgorithmName_AES() {
		SymmetricAlgorithmEnum alg = SymmetricAlgorithmEnum.getSymmetricAlgorithm("AES/ECB/PKCS5Padding");
		assertNotNull(alg);
		assertEquals(SymmetricAlgorithmEnum.AES, alg);
	}

	@Test
	public void testResolveByAlgorithmName_caseInsensitive() {
		SymmetricAlgorithmEnum alg = SymmetricAlgorithmEnum.getSymmetricAlgorithm("aes/ecb/pkcs5padding");
		assertNotNull(alg);
		assertEquals(SymmetricAlgorithmEnum.AES, alg);
	}

	@Test
	public void testResolveByAlgorithmName_TripleDES() {
		SymmetricAlgorithmEnum alg = SymmetricAlgorithmEnum.getSymmetricAlgorithm("DESede/ECB/PKCS5Padding");
		assertNotNull(alg);
		assertEquals(SymmetricAlgorithmEnum.TRI_DES, alg);
	}

	@Test
	public void testUnknownAlgorithm_returnsNull() {
		assertNull(SymmetricAlgorithmEnum.getSymmetricAlgorithm("UNKNOWN"));
	}
}
