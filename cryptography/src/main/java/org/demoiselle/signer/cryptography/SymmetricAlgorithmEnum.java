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
 * FIXME maybe a better name is just SymmetricAlgorithm
 * Defines the algorithms used for ICP-Brasil (PKI) standard symmetric encryption.
 * <p>
 * Private Document Security of the Proprietary Entity and its Normative Backup
 * ICP-Brasil = DOC-ICP-04 - item 6.1.1.3, DOC-ICP-04 - item 6.2.4.3, DOC-ICP-05 - item 6.2.4.4
 * Algorithm e Key size = 3DES - 112 bits, AES - 128 or
 * 256 bits Operating mode = CBC or GCM
 * For more information, read document ICP-BRAZIL CRYPTOGRAPHY PATTERNS AND ALGORITHMS (DOC ICP-01.01)
 */
public enum SymmetricAlgorithmEnum {

	TRI_DES("DESede", "DESede/ECB/PKCS5Padding", 112),
	AES("AES", "AES/ECB/PKCS5Padding", 128);

	/**
	 * Definition of standard algorithm.
	 */
	public static SymmetricAlgorithmEnum DEFAULT = SymmetricAlgorithmEnum.AES;

	private String keyAlgorithm;
	private String algorithm;
	private int size;

	SymmetricAlgorithmEnum(String keyAlgorithm, String algorithm, int size) {
		this.keyAlgorithm = keyAlgorithm;
		this.algorithm = algorithm;
		this.size = size;
	}

	public String getAlgorithm() {
		return this.algorithm;
	}

	public String getKeyAlgorithm() {
		return keyAlgorithm;
	}

	public int getSize() {
		return size;
	}

	/**
	 * Retrieves an item from the enumeration corresponding to the passed parameter.
	 * The passed parameter must be equal (case insensitive) to the algorithm name
	 * of any item in this enumeration, otherwise it will return null.
	 *
	 * @param algorithm name
	 * @return representation
	 */
	public static SymmetricAlgorithmEnum getSymmetricAlgorithm(String algorithm) {
		for (SymmetricAlgorithmEnum value : SymmetricAlgorithmEnum.values())
			if (value.getAlgorithm().equalsIgnoreCase(algorithm))
				return value;
		return null;
	}
}
