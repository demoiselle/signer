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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;

/**
 * Extended Validation Data
 * <p>
 * Certificate Values Attribute Definition
 * <p>
 * The Certificate Values attribute is an unsigned attribute.  Only a
 * single instance of this attribute must occur with an electronic
 * signature.  It holds the values of certificates referenced in the
 * CompleteCertificateRefs attribute.
 * <p>
 * Note: If an Attribute Certificate is used, it is not provided in this
 * structure but must be provided by the signer as a signer-attributes
 * attribute (see clause 12.3).
 * <p>
 * The following object identifier identifies the CertificateValues
 * attribute:
 * <p>
 * id-aa-ets-certValues OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 23}
 *
 * @author 07721825741
 */
public class CertValues implements UnsignedAttribute {

	private final ASN1ObjectIdentifier identifier = PKCSObjectIdentifiers.id_aa_ets_certValues;
	private Certificate[] certificates = null;
//    private static MessagesBundle cadesMessagesBundle = new MessagesBundle();

	@Override
	public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content, SignaturePolicy signaturePolicy, byte[] hash) {
		this.certificates = certificates;
	}

	@Override
	public String getOID() {
		return identifier.getId();
	}

	@Override
	public Attribute getValue() throws SignerException {

		List<org.bouncycastle.asn1.x509.Certificate> certificateValues = new ArrayList<org.bouncycastle.asn1.x509.Certificate>();
		try {

			int chainSize = certificates.length - 1;
			for (int i = 0; i < chainSize; i++) {
				X509Certificate cert = (X509Certificate) certificates[i];
				byte data[] = cert.getEncoded();
				certificateValues.add(org.bouncycastle.asn1.x509.Certificate.getInstance(data));
			}
			org.bouncycastle.asn1.x509.Certificate[] certValuesArray = new org.bouncycastle.asn1.x509.Certificate[certificateValues.size()];
			return new Attribute(identifier, new DERSet(new DERSequence(certificateValues.toArray(certValuesArray))));
		} catch (CertificateEncodingException e) {
			throw new SignerException(e.getMessage());
		}
	}


}
