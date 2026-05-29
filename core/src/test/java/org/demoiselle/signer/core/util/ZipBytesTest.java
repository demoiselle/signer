package org.demoiselle.signer.core.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

public class ZipBytesTest {

	@Test
	public void testCompressing_singleFile() {
		Map<String, byte[]> files = new HashMap<>();
		files.put("file.txt", "content here".getBytes());

		byte[] compressed = ZipBytes.compressing(files);

		assertNotNull(compressed);
		assertTrue(compressed.length > 0);
	}

	@Test
	public void testDecompressing_producesOriginalContent() {
		Map<String, byte[]> files = new HashMap<>();
		byte[] content = "decompressed content".getBytes();
		files.put("test.txt", content);

		byte[] compressed = ZipBytes.compressing(files);
		Map<String, byte[]> result = ZipBytes.decompressing(compressed);

		assertNotNull(result);
		assertEquals(1, result.size());
		assertTrue(result.containsKey("test.txt"));
		assertArrayEquals(content, result.get("test.txt"));
	}

	@Test
	public void testRoundTrip_multipleFiles() {
		Map<String, byte[]> files = new HashMap<>();
		files.put("alpha.txt", "alpha content".getBytes());
		files.put("beta.bin", new byte[]{1, 2, 3, 4, 5});

		byte[] compressed = ZipBytes.compressing(files);
		Map<String, byte[]> result = ZipBytes.decompressing(compressed);

		assertEquals(2, result.size());
		assertArrayEquals("alpha content".getBytes(), result.get("alpha.txt"));
		assertArrayEquals(new byte[]{1, 2, 3, 4, 5}, result.get("beta.bin"));
	}

	@Test
	public void testCompressingEmptyMap_returnsNonNull() {
		Map<String, byte[]> files = new HashMap<>();
		byte[] compressed = ZipBytes.compressing(files);
		assertNotNull(compressed);
	}

	@Test
	public void testRoundTrip_binaryData() {
		Map<String, byte[]> files = new HashMap<>();
		byte[] binaryData = new byte[256];
		for (int i = 0; i < 256; i++) {
			binaryData[i] = (byte) i;
		}
		files.put("binary.bin", binaryData);

		byte[] compressed = ZipBytes.compressing(files);
		Map<String, byte[]> result = ZipBytes.decompressing(compressed);

		assertArrayEquals(binaryData, result.get("binary.bin"));
	}

	@Test
	public void testRoundTrip_largeContent() {
		Map<String, byte[]> files = new HashMap<>();
		byte[] largeContent = new byte[100_000];
		for (int i = 0; i < largeContent.length; i++) {
			largeContent[i] = (byte) (i % 256);
		}
		files.put("large.bin", largeContent);

		byte[] compressed = ZipBytes.compressing(files);
		Map<String, byte[]> result = ZipBytes.decompressing(compressed);

		assertArrayEquals(largeContent, result.get("large.bin"));
	}
}
