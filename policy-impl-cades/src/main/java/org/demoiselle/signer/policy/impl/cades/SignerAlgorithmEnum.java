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

package org.demoiselle.signer.policy.impl.cades;

import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;

/**
 * Enumeration for suported Algorrithm
 */
public enum SignerAlgorithmEnum {

	/**
	 * 1.2.840.113549.1.9.4 OIDs dos algoritmos SHA1 = 1.3.14.3.2.26 SHA256 =
	 * 2.16.840.1.101.3.4.2.1 SHA512 = 2.16.840.1.101.3.4.2.3 MD5 =
	 * 1.2.840.113549.2.5 DSA = 1.2.840.10040.4.3 RSA = 1.2.840.113549.1.1.1
	 * ECDSA = 1.0.14888.3.0.4
	 */
	SHA1withDSA("SHA1withDSA", DigestAlgorithmEnum.SHA_1.getAlgorithm(), "1.3.14.3.2.26", "DSA", "1.2.840.10040.4.3"),
	SHA1withRSA("SHA1withRSA", DigestAlgorithmEnum.SHA_1.getAlgorithm(), "1.3.14.3.2.26", "RSA", "1.2.840.113549.1.1.1"),
	SHA256withRSA("SHA256withRSA", DigestAlgorithmEnum.SHA_256.getAlgorithm(), "2.16.840.1.101.3.4.2.1", "RSA", "1.2.840.113549.1.1.1"),
	SHA256withECDSA("SHA256withECDSA", DigestAlgorithmEnum.SHA_256.getAlgorithm(), "2.16.840.1.101.3.4.2.1", "ECDSA", "1.0.14888.3.0.4"),
	SHA512withRSA("SHA512withRSA", DigestAlgorithmEnum.SHA_512.getAlgorithm(), "2.16.840.1.101.3.4.2.3", "RSA", "1.2.840.113549.1.1.1"),
	SHA512withECDSA("SHA512withECDSA", DigestAlgorithmEnum.SHA_512.getAlgorithm(), "2.16.840.1.101.3.4.2.3", "ECDSA", "1.0.14888.3.0.4");

	/**
	 * Definition of standard algorithm.
	 */
	public static SignerAlgorithmEnum DEFAULT = SignerAlgorithmEnum.SHA512withRSA;

	private String algorithm;
	private String algorithmHash;
	private String OIDAlgorithmHash;
	private String algorithmCipher;
	private String OIDAlgorithmCipher;

	SignerAlgorithmEnum(String algorithm, String algorithmHash, String OIDAlgorithmHash, String algorithmCipher, String OIDAlgorithmCipher) {

		this.algorithm = algorithm;
		this.algorithmHash = algorithmHash;
		this.algorithmCipher = algorithmCipher;
		this.OIDAlgorithmCipher = OIDAlgorithmCipher;
		this.OIDAlgorithmHash = OIDAlgorithmHash;
	}

	public String getOIDAlgorithmHash() {
		return OIDAlgorithmHash;
	}

	public String getOIDAlgorithmCipher() {
		return OIDAlgorithmCipher;
	}

	public String getAlgorithm() {
		return this.algorithm;
	}

	public String getAlgorithmHash() {
		return algorithmHash;
	}

	public String getAlgorithmCipher() {
		return algorithmCipher;
	}

	/**
	 * Retrieves an item from the enumeration corresponding to the parameter,
	 * which is the name of the algorithm (eg SHA256withRSA).
	 * The passed parameter must be equal (case insensitive) to
	 * the algorithm name of any item in this enumeration, otherwise it will return null.
	 *
	 * @param algorithm algorithm name
	 * @return SignatureALgorithmEnum specific enum value for name
	 */
	public static SignerAlgorithmEnum getSignerAlgorithmEnum(String algorithm) {
		for (SignerAlgorithmEnum value : SignerAlgorithmEnum.values()) {
			if (value.getAlgorithm().equalsIgnoreCase(algorithm)) {
				return value;
			}
		}
		return null;
	}

	/**
	 * Retrieves an item from the enumeration corresponding to the parameter,
	 * which is the OID of the algorithm (ex: 2.16.840.1.101.3.4.2.1).
	 * The passed parameter must be equal (case insensitive) to
	 * the OID of the algorithm of some item of this enumeration, otherwise it will return null.
	 *
	 * @param OIDalgorithm OID String representation
	 * @return SignerAlgorithmEnum specific enum value for oid
	 */
	public static SignerAlgorithmEnum getSignerOIDAlgorithmHashEnum(String OIDalgorithm) {
		for (SignerAlgorithmEnum value : SignerAlgorithmEnum.values()) {
			if (value.getOIDAlgorithmHash().equalsIgnoreCase(OIDalgorithm)) {
				return value;
			}
		}
		return null;
	}
}
