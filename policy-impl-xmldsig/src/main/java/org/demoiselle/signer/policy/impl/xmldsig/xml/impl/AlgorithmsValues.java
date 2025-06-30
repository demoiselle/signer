/*
 * Demoiselle Framework
 * Copyright (C) 2025 SERPRO
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

package org.demoiselle.signer.policy.impl.xmldsig.xml.impl;

import java.util.HashMap;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;

/**
 * * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public class AlgorithmsValues {

	static HashMap<String, String> signatureDigest = null;
	static HashMap<String, String> signatureAlgorithms = null;
	static HashMap<String, String> algorithmsOnSignature = null;
	static HashMap<String, String> digestTosignature = null;

	static void loadMethodsData() {
		digestTosignature = new HashMap<String, String>();
		digestTosignature.put("SHA1withRSA", "SHA-1");
		digestTosignature.put("SHA256withRSA", "SHA-256");

		signatureDigest = new HashMap<String, String>();
		signatureDigest.put("SHA-1", DigestMethod.SHA1);
		signatureDigest.put("SHA-256", DigestMethod.SHA256);

		signatureAlgorithms = new HashMap<String, String>();
		signatureAlgorithms.put("SHA1withRSA", SignatureMethod.RSA_SHA1);
		signatureAlgorithms.put("SHA256withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		
		algorithmsOnSignature = new HashMap<String, String>();
		algorithmsOnSignature.put(SignatureMethod.RSA_SHA1, "SHA1withRSA");
		algorithmsOnSignature.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "SHA256withRSA");
	}

	static final String getdigestTosignature(String value) {
		if (digestTosignature == null) {
			loadMethodsData();
		}
		return digestTosignature.containsKey(value) ? digestTosignature.get(value) : "not implemented";
	}

	static final String getSignatureDigest(String value) {
		if (signatureDigest == null) {
			loadMethodsData();
		}
		return signatureDigest.containsKey(value) ? signatureDigest.get(value) : "not implemented";
	}
	
	static final String getSignatureAlgorithm(String value) {
		if (signatureAlgorithms == null) {
			loadMethodsData();
		}
		return signatureAlgorithms.containsKey(value) ? signatureAlgorithms.get(value) : "not implemented";
	}
	
	static final String getAlgorithmsOnSignature(String value) {
		if (algorithmsOnSignature == null) {
			loadMethodsData();
		}
		return algorithmsOnSignature.containsKey(value) ? algorithmsOnSignature.get(value) : "not implemented";
	}

}
