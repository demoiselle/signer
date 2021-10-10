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

package org.demoiselle.signer.cryptography;

/**
 * Defines the algorithms used for standard ICP-Brazil asymmetric encryption
 * For more information, read ICP-BRAZIL'S CRYPTOGRAPHIC PATTERNS AND ALGORITHMS (DOC ICP-01.01)
 * Generation of AC Asymmetric Keys ICP-Brazil Standard = DOC-ICP-01 - item 6.1.1.3,
 * DOC-ICP-04 - item 6.1.1.3, DOC-ICP-01 - item 6.1.5, DOC-ICP-05 - item 6.1.5
 * Algorithm = RSA, ECDSA (according to RFC 5480)
 * Key size = RSA 2048, RSA 4096, ECDSA 512
 * End-User Asymmetric Key Generation
 * ICP-Brazil Standard = DOC-ICP-04 - item 6.1.5.2
 * Algorithm = RSA, ECDSA (according to RFC 5480)
 * Key size A1, A2, A3, S1, S2, S3, T3 = RSA 1024, RSA 2048, ECDSA 256
 * Key size A4, S4, T4 = RSA 2048, RSA 4096, ECDSA 512
 */
public enum AsymmetricAlgorithmEnum {

	/**
	 * <a href="http://www.rsa.com/rsalabs/node.asp?id=2125">http://www.rsa.com/
	 * rsalabs/node.asp?id=2125</a>
	 */
	RSA("RSA/ECB/PKCS1Padding"),
	// RSA 1024, RSA 2048, RSA 4096

	/**
	 * <a href="http://www.faqs.org/rfcs/rfc4050.html">http://www.faqs.org/rfcs/
	 * rfc4050.html</a>
	 */
	ECDSA("ECDSA");
	// ECDSA 256, ECDSA 512

	/**
	 * Definition of standard algorithm.
	 */
	public static AsymmetricAlgorithmEnum DEFAULT = AsymmetricAlgorithmEnum.RSA;

	private String algorithm;

	private AsymmetricAlgorithmEnum(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Retrieves an item from the enumeration corresponding to the passed parameter.
	 * The passed parameter must be equal (case insensitive) to the algorithm name of
	 * any item in this enumeration, otherwise it will return null.
	 *
	 * @param algorithm algorithm name
	 * @return algorithm representation
	 */
	public static AsymmetricAlgorithmEnum getAsymmetricAlgorithmEnum(String algorithm) {
		for (AsymmetricAlgorithmEnum value : AsymmetricAlgorithmEnum.values()) {
			if (value.getAlgorithm().equalsIgnoreCase(algorithm)) {
				return value;
			}
		}
		return null;
	}

}
