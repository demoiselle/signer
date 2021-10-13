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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
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
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.SignedAttribute;

/**
 * ESS signing-certificate-v2 Attribute Definition
 *
 * The ESS signing-certificate-v2 attribute is similar to the ESS
 * signing-certificate defined above, except that this attribute can be used
 * with hashing algorithms other than SHA-1.
 *
 * The syntax of the signing-certificate-v2 attribute type of the ES is as
 * defined in "ESS Update: Adding CertID Algorithm Agility", RFC 5035 [15], and
 * further qualified in the present document.
 *
 * The sequence of the policy information field is not used in the present
 * document.
 *
 * This attribute shall be used in the same manner as defined above for the ESS
 * signing-certificate attribute.
 *
 * The object identifier for this attribute is: id-aa-signingCertificateV2
 * OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
 * pkcs9(9) smime(16) id-aa(2) 47 } *
 */
public class SigningCertificateV2 implements SignedAttribute {

	// private static final Logger logger =
	// LoggerFactory.getLogger(SigningCertificateV2.class);
	private final ASN1ObjectIdentifier identifier = PKCSObjectIdentifiers.id_aa_signingCertificateV2;
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
			X509Certificate cert = (X509Certificate) certificates[0];
			X509Certificate issuerCert = (X509Certificate) certificates[1];
			Digest digest = DigestFactory.getInstance().factoryDefault();
			digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
			byte[] certHash = digest.digest(cert.getEncoded());
			X500Name dirName =new JcaX509CertificateHolder(issuerCert).getSubject();
			GeneralName name = new GeneralName(dirName);
			GeneralNames issuer = new GeneralNames(name);
			ASN1Integer serialNumber = new ASN1Integer(cert.getSerialNumber());
			IssuerSerial issuerSerial = new IssuerSerial(issuer, serialNumber);
			AlgorithmIdentifier algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);// SHA-256
			ESSCertIDv2 essCertIDv2 = new ESSCertIDv2(algId, certHash, issuerSerial);

			org.bouncycastle.asn1.ess.SigningCertificateV2  signingCertificateV2 = new org.bouncycastle.asn1.ess.SigningCertificateV2(essCertIDv2);

			return new Attribute(identifier, new DERSet(signingCertificateV2));


		} catch (CertificateEncodingException ex) {
			throw new SignerException(ex.getMessage());
		}
	}
}
