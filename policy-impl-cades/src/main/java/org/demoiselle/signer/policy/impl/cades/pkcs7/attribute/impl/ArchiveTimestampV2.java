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

package org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.impl;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.asn1.cms.Attribute;
import org.demoiselle.signer.core.timestamp.TimeStampGenerator;
import org.demoiselle.signer.core.timestamp.TimeStampGeneratorSelector;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;

/**
 * archive-time-stamp Attribute Definition.
 *
 * <p>The archive-time-stamp attribute is a time-stamp token of many of the
 * elements of the signedData in the electronic signature.  If the
 * certificate-values and revocation-values attributes are not present
 * in the CAdES-BES or CAdES-EPES, then they shall be added to the
 * electronic signature prior to computing the archive time-stamp token.</p>
 *
 * <p>The archive-time-stamp attribute is an unsigned attribute.  Several
 * instances of this attribute may occur with an electronic signature
 * both over time and from different TSUs.</p>
 *
 * <p>The following object identifier identifies the nested
 * archive-time-stamp attribute:</p>
 *
 * <pre>
 *   id-aa-ets-archiveTimestampV2  OBJECT IDENTIFIER ::=
 *    { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
 *     smime(16) id-aa(2) 48}
 *
 *     Archive-time-stamp attribute values have the ASN.1 syntax ArchiveTimeStampToken
 *     ArchiveTimeStampToken ::= TimeStampToken
 * </pre>
 */
public class ArchiveTimestampV2 implements UnsignedAttribute {

	private final String identifier = "1.2.840.113549.1.9.16.2.48";
	private static MessagesBundle cadesMessagesBundle = new MessagesBundle();
	private static final TimeStampGenerator timeStampGenerator = TimeStampGeneratorSelector.selectReference();
	private PrivateKey privateKey = null;
	private Certificate[] certificates = null;

	@Override
	public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy, byte[] hash) {
	}

	@Override
	public String getOID() {
		return identifier;
	}

	@Override
	public Attribute getValue() throws SignerException {
		throw new UnsupportedOperationException(cadesMessagesBundle.getString("error.not.supported", getClass().getName()));
	}
}
