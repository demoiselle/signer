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

package org.demoiselle.signer.policy.impl.cades.pkcs7;

import java.security.cert.Certificate;

import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.Signer;

/**
 * Basic specification for implementing digital signatures in PKCS7 Format.
 */
public interface PKCS7Signer extends Signer {

	/**
	 * Assign a Certificate for validate or generate a signature
	 *
	 * @param certificate certificate to be used
	 */
	void setCertificates(Certificate[] certificate);

	/**
	 * Assign a Policy for validate or generate a signature
	 *
	 * @param signaturePolicy Signature policy to be used
	 */
	void setSignaturePolicy(Policies signaturePolicy);

	/**
	 * Generates a digital co-signature from a content,
	 * the result file does not contains the content that was signed
	 *
	 * @param content       content to be signed
	 * @param previewSigned CMS content from preview signed
	 * @return detached signature
	 */
	byte[] doDetachedSign(byte[] content, byte[] previewSigned);

	/**
	 * Generates a digital co-signature from a content and attaches this content on result file
	 *
	 * @param content       content to be signed
	 * @param previewSigned CMS content from preview signed
	 * @return attached signature
	 */
	byte[] doAttachedSign(byte[] content, byte[] previewSigned);

	/**
	 * Generates a digital couter-signature
	 *
	 * @param previewCMSSignature CMS content from preview signed
	 * @return new CMS Signature bytes
	 */
	byte[] doCounterSign(byte[] previewCMSSignature);

	/**
	 * Generates a digital signature from a previous calculated hash for a content,
	 * the result file does not contains the original content that was signed
	 *
	 * @param hash hash to be signed
	 * @return detached PCKS7 signature
	 */
	byte[] doHashSign(byte[] hash);

	/**
	 * Generates a digital co-signature from a previous calculated hash for a content,
	 * and its previous signatures
	 * the result file does not contains the original content that was signed
	 *
	 * @param hash          hash to be signed
	 * @param previewSigned previous signature
	 * @return detached PCKS7 signature
	 */
	byte[] doHashCoSign(byte[] hash, byte[] previewSigned);

	/**
	 * Assign a Certificate for get timeStamp
	 *
	 * @param certificates certificate to be used
	 */
	void setCertificatesForTimeStamp(Certificate[] certificates);
}
