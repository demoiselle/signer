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
 * FIXME maybe a better name is just DigestAlgorithm
 * Defines the Digest algorithms,
 * according to the standard defined by the Brazilian public key infrastructure (ICP-Brasil).
 */
public enum DigestAlgorithmEnum {

	MD5("MD5"),
	SHA_1("SHA-1"),
	SHA_224("SHA224"),
	SHA_256("SHA-256"),
	SHA_384("SHA384"),
	SHA_512("SHA-512"),
	SHA3_224("SHA3-224"),
	SHA3_256("SHA3-256"),
	SHA3_384("SHA3-384"),
	SHA3_512("SHA3-512"),
	SHAKE_128("SHAKE128"),
	SHAKE_256("SHAKE256");

	public static DigestAlgorithmEnum DEFAULT = DigestAlgorithmEnum.SHA_256;

	private String algorithm;

	DigestAlgorithmEnum(String algorithm) {
		this.algorithm = algorithm;
	}

	public String getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Retrieves an enumeration item that matches the passed parameter.
	 * The passed parameter must be equal (case insensitive)
	 * to the algorithm name of any item in this enumeration, otherwise it will return null.
	 *
	 * @param algorithm algorithm name
	 * @return algorithm representation
	 */
	public static DigestAlgorithmEnum getDigestAlgorithmEnum(String algorithm) {
		for (DigestAlgorithmEnum value : DigestAlgorithmEnum.values())
			if (value.getAlgorithm().equalsIgnoreCase(algorithm))
				return value;
		return null;
	}

}
