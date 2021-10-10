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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.factory.DigestFactory;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.UnsignedAttribute;

/**
 * Complete Certificate Refs Attribute Definition
 * <p>
 * The Complete Certificate Refs attribute is an unsigned attribute.
 * It references the full set of CA certificates that have been used to
 * validate a ES with Complete validation data (ES-C) up to (but not
 * including) the signer's certificate.  Only a single instance of this
 * attribute must occur with an electronic signature.
 * <p>
 * Note: The signer's certified is referenced in the signing certificate
 * attribute (see clause 3.1 https://www.ietf.org/rfc/rfc3126.txt)
 * <p>
 * id-aa-ets-certificateRefs OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 21}
 * <p>
 * The complete certificate refs attribute value has the ASN.1 syntax  CompleteCertificateRefs.
 * <p>
 * CompleteCertificateRefs ::=  SEQUENCE OF OTHERCertID
 * <p>
 * OTHERCertID is defined in clause 3.8.2.
 * <p>
 * OtherCertID ::= SEQUENCE {
 * otherCertHash            OtherHash,
 * issuerSerial             IssuerSerial OPTIONAL }
 * <p>
 * The IssuerSerial that must be present in OTHERCertID.
 * The certHash  must match the hash of the certificate referenced.
 */
public class CertificateRefs implements UnsignedAttribute {

	private final ASN1ObjectIdentifier identifier = PKCSObjectIdentifiers.id_aa_ets_certificateRefs;

	private Certificate[] certificates = null;

	@Override
	public void initialize(PrivateKey privateKey, Certificate[] certificates, byte[] content,
						   SignaturePolicy signaturePolicy, byte[] hash) {
		this.certificates = certificates;
	}

	@Override
	public String getOID() {
		return identifier.getId();
	}

	@Override
	public Attribute getValue() throws SignerException {

		try {
			int chainSize = certificates.length - 1;
			OtherCertID[] arrayOtherCertID = new OtherCertID[chainSize];
			for (int i = 1; i <= chainSize; i++) {
				X509Certificate issuerCert = null;
				X509Certificate cert = (X509Certificate) certificates[i];
				if (i < chainSize) {
					issuerCert = (X509Certificate) certificates[i + 1];
				} else { // raiz
					issuerCert = (X509Certificate) certificates[i];
				}
				Digest digest = DigestFactory.getInstance().factoryDefault();
				digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
				byte[] certHash = digest.digest(cert.getEncoded());
				//X500Name dirName = new X500Name(issuerCert.getSubjectX500Principal().getName());
				X500Name dirName = new JcaX509CertificateHolder(issuerCert).getSubject();
				GeneralName name = new GeneralName(dirName);
				GeneralNames issuer = new GeneralNames(name);
				ASN1Integer serialNumber = new ASN1Integer(cert.getSerialNumber());
				IssuerSerial issuerSerial = new IssuerSerial(issuer, serialNumber);
				AlgorithmIdentifier algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
				OtherCertID otherCertID = new OtherCertID(algId, certHash, issuerSerial);
				arrayOtherCertID[i - 1] = otherCertID;
			}

			return new Attribute(identifier, new DERSet(new ASN1Encodable[]{new DERSequence(arrayOtherCertID)}));
		} catch (CertificateEncodingException e) {
			throw new SignerException(e.getMessage());
		}
	}
}
