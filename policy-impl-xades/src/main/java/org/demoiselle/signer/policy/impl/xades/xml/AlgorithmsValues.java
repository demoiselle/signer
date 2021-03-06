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

package org.demoiselle.signer.policy.impl.xades.xml;

import java.util.HashMap;

import org.apache.xml.security.c14n.Canonicalizer;
/**
 ** @author Fabiano Kuss <fabiano.kuss@serpro.gov.br> 
 */

public class AlgorithmsValues {
	static HashMap<String, String> signatureMethods = null;
	static HashMap<String, String> digestMethods = null;
	static HashMap<String, String> signatureAlgorithms = null;
	
	static void loadMethodsData() {
		
		signatureMethods = new HashMap<String, String>();
		
		signatureMethods.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA-1");
		signatureMethods.put("http://www.w3.org/2009/xmldsig11#dsa-sha256", "SHA-256");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", "MD5");
		signatureMethods.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA-1");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", "sha-224");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA-256");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA-384");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA-212");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160", "RIPEMD160");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", "SHA-1");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224", "SHA-224");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA-256");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "SHA-384");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "SHA-512");
		signatureMethods.put("http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160", "RIPEMD160");
		
		
		digestMethods = new HashMap<String, String>();
		
		digestMethods.put("http://www.w3.org/2001/04/xmlenc#sha1", "SHA-1");
		digestMethods.put("http://www.w3.org/2001/04/xmlenc#sha256", "SHA-256");
		digestMethods.put("http://www.w3.org/2001/04/xmlenc#sha212", "SHA-512");
		digestMethods.put("http://www.w3.org/2001/04/xmlenc#ripemd160", "RIPEMD160");
		
		signatureAlgorithms = new HashMap<String, String>();
		
		
		signatureAlgorithms.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
		signatureAlgorithms.put("http://www.w3.org/2009/xmldsig11#dsa-sha256", "SHA256withDSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", "MD5withRSA");
		signatureAlgorithms.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha224", "SHA224withRSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "SHA384withRSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "SHA512withRSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160", "RIPEMD160withRSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", "SHA1withECDSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224", "SHA244withECDSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "SHA256withECDSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "SHA348withECDSA");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "SHA512withECDSA");
		signatureAlgorithms.put("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha224", "HmacSHA224");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512");
		signatureAlgorithms.put("http://www.w3.org/2001/04/xmldsig-more#hmac-ripemd160", "HmacRIPEMD160");
	}
	
	final static String getSignatureMethod(String method) {
		
		if(signatureMethods == null) {
			loadMethodsData();
		}
		
		return signatureMethods.containsKey(method) ? signatureMethods.get(method) : null;
		
	}
	
	final static String getSignatureDigest(String value) {
		
		if(digestMethods == null) {
			loadMethodsData();
		}
		
		return digestMethods.containsKey(value) ? digestMethods.get(value) : null;
		
	}
	
	final static String getSignatureAlgorithm(String value) {
		
		if(signatureAlgorithms == null) {
			loadMethodsData();
		}
		
		return signatureAlgorithms.containsKey(value) ? signatureAlgorithms.get(value) : null;
		
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