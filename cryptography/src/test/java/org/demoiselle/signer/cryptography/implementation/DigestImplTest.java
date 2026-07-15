package org.demoiselle.signer.cryptography.implementation;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;

import org.demoiselle.signer.cryptography.CryptographyException;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

public class DigestImplTest {

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testDigest_withDefaultAlgorithm_returnsExpectedHash() throws Exception {
		DigestImpl impl = new DigestImpl();
		byte[] content = "hello".getBytes("UTF-8");

		byte[] result = impl.digest(content);

		assertNotNull(result);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] expected = md.digest(content);
		assertArrayEquals(expected, result);
	}

	@Test
	public void testDigest_nullContent_throwsCryptographyException() {
		DigestImpl impl = new DigestImpl();
		thrown.expect(CryptographyException.class);
		impl.digest(null);
	}

	@Test
	public void testDigestHex_returnsHexString() {
		DigestImpl impl = new DigestImpl();
		String hex = impl.digestHex("test".getBytes());

		assertNotNull(hex);
		assertTrue(hex.matches("[0-9a-f]+"));
		assertEquals(64, hex.length()); // SHA-256 = 32 bytes = 64 hex chars
	}

	@Test
	public void testDigest_withSHA1Algorithm() throws Exception {
		DigestImpl impl = new DigestImpl();
		impl.setAlgorithm("SHA-1");
		byte[] content = "hello".getBytes("UTF-8");

		byte[] result = impl.digest(content);

		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] expected = md.digest(content);
		assertArrayEquals(expected, result);
		assertEquals(20, result.length); // SHA-1 = 20 bytes
	}

	@Test
	public void testDigest_withEnumAlgorithm() throws Exception {
		DigestImpl impl = new DigestImpl();
		impl.setAlgorithm(DigestAlgorithmEnum.SHA_512);
		byte[] content = "data".getBytes("UTF-8");

		byte[] result = impl.digest(content);

		assertNotNull(result);
		assertEquals(64, result.length); // SHA-512 = 64 bytes
	}

	@Test
	public void testDigestFile_returnsCorrectHash() throws IOException, Exception {
		DigestImpl impl = new DigestImpl();
		File file = tempFolder.newFile("testfile.txt");
		byte[] fileContent = "file content for digest".getBytes("UTF-8");
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write(fileContent);
		}

		byte[] result = impl.digestFile(file);

		assertNotNull(result);
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] expected = md.digest(fileContent);
		assertArrayEquals(expected, result);
	}

	@Test
	public void testDigestFile_nonExistentFile_throwsCryptographyException() {
		DigestImpl impl = new DigestImpl();
		File missing = new File("/nonexistent/file.txt");
		thrown.expect(CryptographyException.class);
		impl.digestFile(missing);
	}

	@Test
	public void testDigestFileHex_returnsHexString() throws IOException {
		DigestImpl impl = new DigestImpl();
		File file = tempFolder.newFile("hex.txt");
		try (FileOutputStream fos = new FileOutputStream(file)) {
			fos.write("hex test content".getBytes("UTF-8"));
		}

		String hex = impl.digestFileHex(file);

		assertNotNull(hex);
		assertTrue(hex.matches("[0-9a-f]+"));
		assertEquals(64, hex.length()); // SHA-256 default
	}

	@Test
	public void testDigest_emptyBytes_doesNotThrow() {
		DigestImpl impl = new DigestImpl();
		byte[] result = impl.digest(new byte[0]);
		assertNotNull(result);
	}

	@Test
	public void testDigestHex_differentInputs_produceDifferentHashes() {
		DigestImpl impl = new DigestImpl();
		String hex1 = impl.digestHex("input1".getBytes());
		String hex2 = impl.digestHex("input2".getBytes());
		assertTrue(!hex1.equals(hex2));
	}
}
