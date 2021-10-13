/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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

package org.demoiselle.signer.policy.impl.xades.xml.impl;

import java.util.HashMap;

import org.apache.xml.security.c14n.Canonicalizer;

/**
 * * @author Fabiano Kuss &lt;fabiano.kuss@serpro.gov.br&gt;
 */
public class AlgorithmsValues {
	static HashMap<String, String> signatureDigest = null;
	static HashMap<String, String> signatureAlgorithms = null;
	static HashMap<String, String> digestTosignature = null;
	static HashMap<String, String> digestMethodsOnSignature = null;
	static HashMap<String, String> algorithmsOnSignature = null;

	// TODO improve another Algorithms

	static void loadMethodsData() {
		digestTosignature = new HashMap<String, String>();

		digestTosignature.put("SHA1withRSA", "SHA-1");
		//digestTosignature.put("SHA224withRSA","SHA-224");
		digestTosignature.put("SHA256withRSA", "SHA-256");
		digestTosignature.put("SHA512withRSA", "SHA-512");

		signatureDigest = new HashMap<String, String>();

		signatureDigest.put("SHA-1", "http://www.w3.org/2001/04/xmlenc#sha1");
		signatureDigest.put("SHA-256", "http://www.w3.org/2001/04/xmlenc#sha256");
		signatureDigest.put("SHA-512", "http://www.w3.org/2001/04/xmlenc#sha512");
		//digestMethods.put("RIPEMD160", "http://www.w3.org/2001/04/xmlenc#ripemd160" );

		digestMethodsOnSignature = new HashMap<String, String>();
		digestMethodsOnSignature.put("http://www.w3.org/2001/04/xmlenc#sha1", "SHA-1");
		digestMethodsOnSignature.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
		digestMethodsOnSignature.put("http://www.w3.org/2001/04/xmlenc#sha512", "SHA-512");
		//digestMethodsOnSignature.put("http://www.w3.org/2001/04/xmlenc#ripemd160", "RIPEMD160" );

		signatureAlgorithms = new HashMap<String, String>();
		//signatureAlgorithms.put("SHA1withDSA","http://www.w3.org/2000/09/xmldsig#dsa-sha1");
		//signatureAlgorithms.put("SHA256withDSA","http://www.w3.org/2009/xmldsig11#dsa-sha256");
		signatureAlgorithms.put("SHA1withRSA", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		//signatureAlgorithms.put("SHA224withRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-sha224");
		signatureAlgorithms.put("SHA256withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		//signatureAlgorithms.put("SHA384withRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
		signatureAlgorithms.put("SHA512withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
		//signatureAlgorithms.put("RIPEMD160withRSA","http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160");
		//signatureAlgorithms.put("SHA1withECDSA","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
		//signatureAlgorithms.put("SHA244withECDSA","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224");
		//signatureAlgorithms.put("SHA256withECDSA","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
		//signatureAlgorithms.put("SHA348withECDSA","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384");
		//signatureAlgorithms.put("SHA512withECDSA","http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
		//signatureAlgorithms.put("HmacSHA1","http://www.w3.org/2000/09/xmldsig#hmac-sha1");
		//signatureAlgorithms.put("HmacSHA224","http://www.w3.org/2001/04/xmldsig-more#hmac-sha224");
		//signatureAlgorithms.put("HmacSHA256","http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
		//signatureAlgorithms.put("HmacSHA384","http://www.w3.org/2001/04/xmldsig-more#hmac-sha384");
		//signatureAlgorithms.put("HmacSHA512","http://www.w3.org/2001/04/xmldsig-more#hmac-sha512");
		//signatureAlgorithms.put("HmacRIPEMD160","http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160");

		algorithmsOnSignature = new HashMap<String, String>();
		//algorithmsOnSignature.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2009/xmldsig11#dsa-sha256", "SHA256withDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", "MD5withRSA");
		algorithmsOnSignature.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", "SHA224withRSA");
		algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
		algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160", "RIPEMD160withRSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", "SHA1withECDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224", "SHA244withECDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA256withECDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "SHA348withECDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "SHA512withECDSA");
		//algorithmsOnSignature.put("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha224", "HmacSHA224");
		//algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256");
		//aAlgorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384");
		//aAlgorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512");
		//aAlgorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160", "HmacRIPEMD160");
	}

	final static String getdigestTosignature(String value) {

		if (digestTosignature == null) {
			loadMethodsData();
		}

		return digestTosignature.containsKey(value) ? digestTosignature.get(value) : "not implemented";
	}

	final static String getSignatureDigest(String value) {

		if (signatureDigest == null) {
			loadMethodsData();
		}

		return signatureDigest.containsKey(value) ? signatureDigest.get(value) : "not implemented";
	}

	final static String getDigestOnSignature(String value) {

		if (digestMethodsOnSignature == null) {
			loadMethodsData();
		}

		return digestMethodsOnSignature.containsKey(value) ? digestMethodsOnSignature.get(value) : "not implemented";
	}

	final static String getAlgorithmsOnSignature(String value) {

		if (algorithmsOnSignature == null) {
			loadMethodsData();
		}

		return algorithmsOnSignature.containsKey(value) ? algorithmsOnSignature.get(value) : "not implemented";
	}

	final static String getSignatureAlgorithm(String value) {

		if (signatureAlgorithms == null) {
			loadMethodsData();
		}

		return signatureAlgorithms.containsKey(value) ? signatureAlgorithms.get(value) : "not implemented";
	}

	final static boolean isCanonicalMethods(String method) {
		switch (method) {
			case Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS:
				return true;
			case Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS:
				return true;
			case Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS:
				return true;
			case Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS:
				return true;
			default:
				return false;
		}
	}

}
