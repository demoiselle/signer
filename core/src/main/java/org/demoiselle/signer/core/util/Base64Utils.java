/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.core.util;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.List;

/**
 * Facilities for Base64 operations.
 */
public class Base64Utils {

	private static final String X509_CERTIFICATE_TYPE = "X.509";
	private static final String CERTIFICATION_CHAIN_ENCODING = "PkiPath";
	private static byte[] mBase64EncMap, mBase64DecMap;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	/*
	 * Class initializer. Initializes the Base64 alphabet (specified in
	 * RFC-2045).
	 */
	static {
		byte[] base64Map = {(byte) 'A', (byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G', (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L', (byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V', (byte) 'W', (byte) 'X',
			(byte) 'Y', (byte) 'Z', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f', (byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u', (byte) 'v', (byte) 'w',
			(byte) 'x', (byte) 'y', (byte) 'z', (byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) '+', (byte) '/'};
		mBase64EncMap = base64Map;
		mBase64DecMap = new byte[128];
		for (int i = 0; i < mBase64EncMap.length; i++) {
			mBase64DecMap[mBase64EncMap[i]] = (byte) i;
		}
	}

	/**
	 *
	 */
	private Base64Utils() {
	}

	/**
	 * Performs encoding in base 64 of a set of bytes
	 *
	 * @param aData of a set of bytes
	 * @return String encoded on base 64
	 */
	public static String base64Encode(byte[] aData) {
		if ((aData == null) || (aData.length == 0)) {
			throw new IllegalArgumentException(coreMessagesBundle.getString("error.base64.encode.null"));
		}

		byte encodedBuf[] = new byte[((aData.length + 2) / 3) * 4];

		// 3-byte to 4-byte conversion
		int srcIndex, destIndex;
		for (srcIndex = 0, destIndex = 0; srcIndex < aData.length - 2; srcIndex += 3) {
			encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex] >>> 2) & 077];
			encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex + 1] >>> 4) & 017 | (aData[srcIndex] << 4) & 077];
			encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex + 2] >>> 6) & 003 | (aData[srcIndex + 1] << 2) & 077];
			encodedBuf[destIndex++] = mBase64EncMap[aData[srcIndex + 2] & 077];
		}

		// Convert the last 1 or 2 bytes
		if (srcIndex < aData.length) {
			encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex] >>> 2) & 077];
			if (srcIndex < aData.length - 1) {
				encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex + 1] >>> 4) & 017 | (aData[srcIndex] << 4) & 077];
				encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex + 1] << 2) & 077];
			} else {
				encodedBuf[destIndex++] = mBase64EncMap[(aData[srcIndex] << 4) & 077];
			}
		}

		// Add padding to the end of encoded data
		while (destIndex < encodedBuf.length) {
			encodedBuf[destIndex] = (byte) '=';
			destIndex++;
		}

		String result = new String(encodedBuf);
		return result;
	}

	/**
	 * Decodes a text in base 64 to a set of bytes
	 *
	 * @param aData Text to be decoded
	 * @return byte[] decoded text
	 */
	public static byte[] base64Decode(String aData) {
		if ((aData == null) || (aData.length() == 0)) {
			throw new IllegalArgumentException(coreMessagesBundle.getString("error.base64.decode.null"));
		}

		byte[] data = aData.getBytes();

		// Skip padding from the end of encoded data
		int tail = data.length;
		while (data[tail - 1] == '=') {
			tail--;
		}

		byte decodedBuf[] = new byte[tail - data.length / 4];

		// ASCII-printable to 0-63 conversion
		for (int i = 0; i < data.length; i++) {
			data[i] = mBase64DecMap[data[i]];
		}

		// 4-byte to 3-byte conversion
		int srcIndex, destIndex;
		for (srcIndex = 0, destIndex = 0; destIndex < decodedBuf.length - 2; srcIndex += 4, destIndex += 3) {
			decodedBuf[destIndex] = (byte) (((data[srcIndex] << 2) & 255) | ((data[srcIndex + 1] >>> 4) & 003));
			decodedBuf[destIndex + 1] = (byte) (((data[srcIndex + 1] << 4) & 255) | ((data[srcIndex + 2] >>> 2) & 017));
			decodedBuf[destIndex + 2] = (byte) (((data[srcIndex + 2] << 6) & 255) | (data[srcIndex + 3] & 077));
		}

		// Handle last 1 or 2 bytes
		if (destIndex < decodedBuf.length) {
			decodedBuf[destIndex] = (byte) (((data[srcIndex] << 2) & 255) | ((data[srcIndex + 1] >>> 4) & 003));
		}
		if (++destIndex < decodedBuf.length) {
			decodedBuf[destIndex] = (byte) (((data[srcIndex + 1] << 4) & 255) | ((data[srcIndex + 2] >>> 2) & 017));
		}

		return decodedBuf;
	}

	/**
	 * Performs the encoding of a certificate chain to base64
	 *
	 * @param aCertificationChain certificate chain
	 * @return ASN.1 DER encoded on Base64, for X.509 certificate
	 * @throws CertificateException exception
	 */
	public static String encodeX509CertChainToBase64(Certificate[] aCertificationChain) throws CertificateException {
		List<Certificate> certList = Arrays.asList(aCertificationChain);
		CertificateFactory certFactory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
		CertPath certPath = certFactory.generateCertPath(certList);
		byte[] certPathEncoded = certPath.getEncoded(CERTIFICATION_CHAIN_ENCODING);
		String base64encodedCertChain = Base64Utils.base64Encode(certPathEncoded);
		return base64encodedCertChain;
	}

}
