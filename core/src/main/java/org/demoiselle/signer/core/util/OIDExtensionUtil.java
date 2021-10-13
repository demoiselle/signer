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

import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 *
 *  For Certificate Extensions:  oid_2_5_29_17 (subjectAltName) and oid_2_5_29_31(cRLDistributionPoints)
 *
 */
public class OIDExtensionUtil {

	private final X509Certificate x509;
	private final Map<String, String> oid_2_5_29_17;
	private final Map<String, String> oid_2_5_29_31;
	private static MessagesBundle coreMessagesBundle = new MessagesBundle();

	public OIDExtensionUtil(X509Certificate x509) {
		this.x509 = x509;
		oid_2_5_29_17 = new HashMap<String, String>();
		oid_2_5_29_31 = new HashMap<String, String>();

		process_2_5_29_17();
		process_2_5_29_31();
	}

	/**
	 * subjectAltName
	 */
	private void process_2_5_29_17() {
		byte[] extension = x509.getExtensionValue("2.5.29.17");

		int extLength = extension.length;
		int extIndex = 0;
		int thisOIDLen = 0;

		if ((extension[6] == -96) || (extension[6] == -127))
			extIndex = 6;
		else if ((extension[5] == -96) || (extension[5] == -127))
			extIndex = 5;
		else if ((extension[4] == -96) || (extension[5] == -127))
			extIndex = 4;
		else {
			return;
		}

		while (extIndex < extLength) {
			if (extension[extIndex] == -96) {
				thisOIDLen = extension[extIndex + 1];

				String oidThird = Integer.toString(extension[extIndex + 5]);
				String oidForth = Integer.toString(extension[extIndex + 6]);
				String oidFifth = Integer.toString(extension[extIndex + 7]);
				String oidSixth = Integer.toString(extension[extIndex + 8]);

				String thisOIDId = new String("2.16" + "." + oidThird + "." + oidForth + "." + oidFifth + "." + oidSixth);

				int thisOIDStart = 0;
				int thisOIDDataLen = 0;
				if (extension[extIndex + 9] == -96) {
					thisOIDDataLen = extension[extIndex + 12];
					thisOIDStart = extIndex + 13;
				} else if (extension[extIndex + 9] == -126) {
					thisOIDDataLen = extension[extIndex + 17];
					thisOIDStart = extIndex + 18;
				} else {
					extIndex += thisOIDLen + 2;
					break;
				}

				String thisOIDData = "";

				try {
					thisOIDData = new String(extension, thisOIDStart, thisOIDDataLen, "ISO8859_1");
				} catch (UnsupportedEncodingException e) {
					throw new CertificateUtilException(coreMessagesBundle.getString("error.encoding.oid", "2.5.29.17"), e);
				}

				oid_2_5_29_17.put(thisOIDId, thisOIDData);
				extIndex += thisOIDLen + 2;
			} else if (extension[extIndex] == -127) {
				String thisRFCId = new String("RFC822");
				int thisRFCDataLen = extension[extIndex + 1];
				String thisRFCData = "";

				try {
					thisRFCData = new String(extension, extIndex + 2, thisRFCDataLen, "ISO8859_1");
				} catch (UnsupportedEncodingException e) {
					throw new CertificateUtilException(coreMessagesBundle.getString("error.encoding.oid", "2.5.29.17"), e);
				}

				oid_2_5_29_17.put(thisRFCId, thisRFCData);
				extIndex += thisRFCDataLen + 2;
			} else {
				extIndex = extLength;
			}
		}
	}

	/**
	 * cRLDistributionPoints
	 */
	private void process_2_5_29_31() {
		byte[] extension = x509.getExtensionValue("2.5.29.31");

		int extIndex = 10;

		if (extension[extIndex] == -122) {
			String thisOIDId = new String("2.5.29.31");
			int thisOIDDataLen = extension[extIndex + 1];
			String thisOIDData = "";

			try {
				thisOIDData = new String(extension, extIndex + 2, thisOIDDataLen, "ISO8859_1");
			} catch (UnsupportedEncodingException e) {
				throw new CertificateUtilException(coreMessagesBundle.getString("error.encoding.oid", "2.5.29.31"), e);
			}

			oid_2_5_29_31.put(thisOIDId, thisOIDData);
		}
	}

	public String getValue(String key) {
		if (key.equals("2.5.29.31")) {
			return oid_2_5_29_31.get(key);
		} else {
			return oid_2_5_29_17.get(key);
		}
	}

	public String getValue(String key, int beginIndex) {
		String value = getValue(key);
		if (value != null) {
			return value.substring(beginIndex);
		} else {
			return null;
		}
	}

	public String getValue(String key, int beginIndex, int endIndex) {
		String value = getValue(key);
		if (value != null) {
			return value.substring(beginIndex, endIndex);
		} else {
			return null;
		}
	}
}
