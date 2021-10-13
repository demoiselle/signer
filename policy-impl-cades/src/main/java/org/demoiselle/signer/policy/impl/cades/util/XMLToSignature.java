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

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignPolicyHash;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedList;

public class XMLToSignature {
	public static SignatureInformations convert(
		Document docPolicy,
		LinkedList<X509Certificate> chain,
		BasicCertificate cert,
		Date signDate,
		LinkedList<String> validatorErrors,
		LinkedList<String> validatorWarnins) {

		SignatureInformations sigInf = new SignatureInformations();

		sigInf.setChain(chain);
		sigInf.setIcpBrasilcertificate(cert);
		//sigInf.setInvalidSignature(invalidSignature);
		sigInf.setNotAfter(cert.getAfterDate());

		NodeList policyDigest = docPolicy.getElementsByTagNameNS("http://www.iti.gov.br/PA#", "SignPolicyDigest");

		if (policyDigest.getLength() > 0) {

			SignaturePolicy sp = new SignaturePolicy();
			SignPolicyHash sph = new SignPolicyHash(null);
			sph.setValue(policyDigest.item(0).getTextContent());
			sp.setSignPolicyHash(sph);

			sigInf.setSignaturePolicy(sp);
		}

		sigInf.setSignDate(signDate);
		sigInf.setTimeStampSigner(null);
		sigInf.setValidatorErrors(validatorErrors);
		sigInf.setValidatorWarnins(validatorWarnins);

		return sigInf;
	}
}
