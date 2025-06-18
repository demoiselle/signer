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

import java.security.Key;
import java.security.cert.Certificate;
import java.util.List;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public class CertificateKeySelector extends KeySelector {
	
	public static class CertificateSelectorResult implements KeySelectorResult {
		
		private Certificate certificate;

		public CertificateSelectorResult(Certificate c) {
			certificate = c;
		}

		@Override
		public Key getKey() {
			return certificate.getPublicKey();
		}
		
		public Certificate getCertificate() {
			return certificate;
		}		
	}

	public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method,
			XMLCryptoContext context) throws KeySelectorException {

		if (keyInfo == null || keyInfo.getContent().isEmpty()) {
			return new CertificateSelectorResult(null);
		}
		SignatureMethod sm = (SignatureMethod) method;
		List<?> list = keyInfo.getContent();

		for (int s = 0; s < list.size(); s++) {
			XMLStructure xmlStructure = (XMLStructure) list.get(s);
			if (!(xmlStructure instanceof X509Data)) {
				continue;
			}
            List<?> x509DataContent = ((X509Data)xmlStructure).getContent();
            for (int c = 0; c < x509DataContent.size(); c++) {
            	Object content = x509DataContent.get(c);
                if (content instanceof Certificate) {
                	CertificateSelectorResult resp = new CertificateSelectorResult((Certificate)content);
                	if (AlgorithmsValues.getAlgorithmsOnSignature(sm.getAlgorithm()).contains(resp.getKey().getAlgorithm())) {
                		return resp;
                	}
                }
            }
		}
		return new CertificateSelectorResult(null);
	}

}
