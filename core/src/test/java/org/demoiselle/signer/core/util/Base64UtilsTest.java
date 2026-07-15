package org.demoiselle.signer.core.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class Base64UtilsTest {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testBase64Encode_basicString() {
		byte[] input = "hello".getBytes();
		String encoded = Base64Utils.base64Encode(input);
		assertNotNull(encoded);
		// Known Base64 encoding of "hello"
		assertEquals("aGVsbG8=", encoded);
	}

	@Test
	public void testBase64Decode_basicString() {
		String encoded = "aGVsbG8=";
		byte[] decoded = Base64Utils.base64Decode(encoded);
		assertArrayEquals("hello".getBytes(), decoded);
	}

	@Test
	public void testRoundTrip_encodeAndDecode() {
		byte[] original = "The quick brown fox".getBytes();
		String encoded = Base64Utils.base64Encode(original);
		byte[] decoded = Base64Utils.base64Decode(encoded);
		assertArrayEquals(original, decoded);
	}

	@Test
	public void testRoundTrip_binaryData() {
		byte[] original = new byte[]{0, 1, 2, 3, 127, (byte) 128, (byte) 255};
		String encoded = Base64Utils.base64Encode(original);
		byte[] decoded = Base64Utils.base64Decode(encoded);
		assertArrayEquals(original, decoded);
	}

	@Test
	public void testBase64Encode_nullInput_throwsIllegalArgumentException() {
		thrown.expect(IllegalArgumentException.class);
		Base64Utils.base64Encode(null);
	}

	@Test
	public void testBase64Encode_emptyInput_throwsIllegalArgumentException() {
		thrown.expect(IllegalArgumentException.class);
		Base64Utils.base64Encode(new byte[0]);
	}

	@Test
	public void testBase64Decode_nullInput_throwsIllegalArgumentException() {
		thrown.expect(IllegalArgumentException.class);
		Base64Utils.base64Decode(null);
	}

	@Test
	public void testBase64Decode_emptyInput_throwsIllegalArgumentException() {
		thrown.expect(IllegalArgumentException.class);
		Base64Utils.base64Decode("");
	}

	@Test
	public void testBase64Encode_outputContainsOnlyBase64Chars() {
		byte[] input = "test data 12345!@#".getBytes();
		String encoded = Base64Utils.base64Encode(input);
		assertTrue(encoded.matches("[A-Za-z0-9+/=]+"));
	}

	@Test
	public void testBase64Encode_lengthIsMultipleOfFour() {
		byte[] input = "any input here".getBytes();
		String encoded = Base64Utils.base64Encode(input);
		assertEquals(0, encoded.length() % 4);
	}

	@Test
	public void testRoundTrip_singleByte() {
		byte[] original = new byte[]{42};
		String encoded = Base64Utils.base64Encode(original);
		byte[] decoded = Base64Utils.base64Decode(encoded);
		assertArrayEquals(original, decoded);
	}

	@Test
	public void testRoundTrip_twoByte() {
		byte[] original = new byte[]{1, 2};
		String encoded = Base64Utils.base64Encode(original);
		byte[] decoded = Base64Utils.base64Decode(encoded);
		assertArrayEquals(original, decoded);
	}
}
