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

package org.demoiselle.signer.policy.impl.cades.util;

/**
 * List of algorithms with their respective OID.
 * <p>
 * http://oid-info.com/basic-search.htm
 */
public enum AlgorithmNames {
	md2("1.2.840.113549.2.1", "MD2"), md2WithRSAEncryption(
		"1.2.840.113549.1.1.2", "MD2withRSA"), md5("1.2.840.113549.2.5",
		"MD5"), md5WithRSAEncryption("1.2.840.113549.1.1.4", "MD5withRSA"), sha1(
		"1.3.14.3.2.26", "SHA1"), sha1WithDSAEncryption(
		"1.2.840.10040.4.3", "SHA1withDSA"), sha1WithECDSAEncryption(
		"1.2.840.10045.4.1", "SHA1withECDSA"), sha1WithRSAEncryption(
		"1.2.840.113549.1.1.5", "SHA1withRSA"), sha224(
		"2.16.840.1.101.3.4.2.4", "SHA224"), sha224WithRSAEncryption(
		"1.2.840.113549.1.1.14", "SHA224withRSA"), sha256(
		"2.16.840.1.101.3.4.2.1", "SHA256"), sha256WithRSAEncryption(
		"1.2.840.113549.1.1.11", "SHA256withRSA"), sha384(
		"2.16.840.1.101.3.4.2.2", "SHA384"), sha384WithRSAEncryption(
		"1.2.840.113549.1.1.12", "SHA384withRSA"), sha512(
		"2.16.840.1.101.3.4.2.3", "SHA512"), sha512WithRSAEncryption(
		"1.2.840.113549.1.1.13", "SHA512withRSA"), sha3_224(
		"2.16.840.1.101.3.4.2.7", "SHA3-224"), sha3_256(
		"2.16.840.1.101.3.4.2.8", "SHA3-256"), sha3_384(
		"2.16.840.1.101.3.4.2.9", "SHA3-384"), sha3_512(
		"2.16.840.1.101.3.4.2.10", "SHA3-512"), shake128(
		"1.0.10118.3.0.62", "SHAKE128"), shake256("1.0.10118.3.0.63",
		"SHAKE256");

	private final String identifier;
	private final String algorithmName;

	AlgorithmNames(String identifier, String name) {
		this.identifier = identifier;
		this.algorithmName = name;
	}

	private String getAlgorithmName() {
		return algorithmName;
	}

	private String getIdentifier() {
		return identifier;
	}

	public static String getAlgorithmNameByOID(String oid) {

		switch (oid) {

			case "1.2.840.113549.2.1": {
				return md2.getAlgorithmName();
			}
			case "1.2.840.113549.2.5": {
				return md5.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.4": {
				return md5WithRSAEncryption.getAlgorithmName();
			}
			case "1.3.14.3.2.26": {
				return sha1.getAlgorithmName();
			}
			case "1.2.840.10040.4.3": {
				return sha1WithDSAEncryption.getAlgorithmName();
			}
			case "1.2.840.10045.4.1": {
				return sha1WithECDSAEncryption.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.5": {
				return sha1WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.4": {
				return sha224.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.14": {
				return sha224WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.1": {
				return sha256.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.11": {
				return sha256WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.2": {
				return sha384.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.12": {
				return sha384WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.3": {
				return sha512.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.13": {
				return sha512WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.7": {
				return sha3_224.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.8": {
				return sha3_256.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.9": {
				return sha3_384.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.10": {
				return sha3_512.getAlgorithmName();
			}
			case "1.0.10118.3.0.62": {
				return shake128.getAlgorithmName();
			}
			case "1.0.10118.3.0.63": {
				return shake256.getAlgorithmName();
			}
			default: {
				return sha256WithRSAEncryption.getAlgorithmName();
			}
		}
	}

	public static String getOIDByAlgorithmName(String algorithmName) {

		switch (algorithmName) {

			case "MD2": {
				return md2.getIdentifier();
			}
			case "MD2withRSA": {
				return md2WithRSAEncryption.getIdentifier();
			}
			case "MD5": {
				return md5.getIdentifier();
			}
			case "MD5withRSA": {
				return md5WithRSAEncryption.getIdentifier();
			}
			case "SHA1": {
				return sha1.getIdentifier();
			}
			case "SHA1withDSA": {
				return sha1WithDSAEncryption.getIdentifier();
			}
			case "SHA1withECDSA": {
				return sha1WithECDSAEncryption.getIdentifier();
			}
			case "SHA1withRSA": {
				return sha1WithRSAEncryption.getIdentifier();
			}
			case "SAH224": {
				return sha224.getIdentifier();
			}
			case "SHA224withRSA": {
				return sha224WithRSAEncryption.getIdentifier();
			}
			case "SHA256": {
				return sha256.getIdentifier();
			}
			case "SHA256withRSA": {
				return sha256WithRSAEncryption.getIdentifier();
			}
			case "SHA384": {
				return sha384.getIdentifier();
			}
			case "SHA384withRSA": {
				return sha384WithRSAEncryption.getIdentifier();
			}
			case "SHA512": {
				return sha512.getIdentifier();
			}
			case "SHA512withRSA": {
				return sha512WithRSAEncryption.getIdentifier();
			}
			case "SHA3-224": {
				return sha3_224.getIdentifier();
			}
			case "SHA3-256": {
				return sha3_256.getIdentifier();
			}
			case "SHA3-384": {
				return sha3_384.getIdentifier();
			}
			case "SHA3-512": {
				return sha3_512.getIdentifier();
			}
			case "SHAKE128": {
				return shake128.getIdentifier();
			}
			case "SHAKE256": {
				return shake256.getIdentifier();
			}
			default: {
				return sha256WithRSAEncryption.getIdentifier();
			}
		}
	}

}
