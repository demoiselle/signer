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

package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS1Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs1.PKCS1Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7TimeStampSigner;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.SignedOrUnsignedAttribute;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.factory.AttributeFactory;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.connector.TimeStampOperator;

/**
 * Basic implementation of Time Stamp on CADES format.
 */
public class CAdESTimeStampSigner implements PKCS7TimeStampSigner {

	// private static final Logger logger =
	// LoggerFactory.getLogger(CAdESTimeStampSigner.class);
	private final PKCS1Signer pkcs1 = PKCS1Factory.getInstance()
		.factoryDefault();
	private SignaturePolicy signaturePolicy;
	private Certificate certificateChain[];
	private ASN1InputStream ais;

	public CAdESTimeStampSigner() {
		this.setSignaturePolicy(Policies.AD_RT_CADES_2_3);
	}

	@Override
	public byte[] doTimeStampForSignature(byte[] signature)
		throws SignerException {
		try {
			Security.addProvider(new BouncyCastleProvider());
			CMSSignedData cmsSignedData = new CMSSignedData(signature);
			SignerInformationStore signers = cmsSignedData.getSignerInfos();
			Iterator<?> it = signers.getSigners().iterator();
			SignerInformation signer = (SignerInformation) it.next();
			AttributeFactory attributeFactory = AttributeFactory.getInstance();
			ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();
			SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
				.factory(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
					.getId());
			signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(),
				this.getCertificateChain(), signer.getSignature(),
				signaturePolicy, null);
			unsignedAttributes.add(signedOrUnsignedAttribute.getValue());
			AttributeTable unsignedAttributesTable = new AttributeTable(
				unsignedAttributes);
			List<SignerInformation> vNewSigners = new ArrayList<SignerInformation>();
			vNewSigners.add(SignerInformation.replaceUnsignedAttributes(signer,
				unsignedAttributesTable));
			SignerInformationStore oNewSignerInformationStore = new SignerInformationStore(
				vNewSigners);
			CMSSignedData oSignedData = cmsSignedData;
			cmsSignedData = CMSSignedData.replaceSigners(oSignedData,
				oNewSignerInformationStore);
			byte[] result = cmsSignedData.getEncoded();
			return result;
		} catch (CMSException ex) {
			throw new SignerException(ex.getMessage());
		} catch (IOException ex) {
			throw new SignerException(ex.getMessage());
		}

	}

	@Override
	public byte[] doTimeStampForContent(byte[] content) {
		try {
			return this.doTimeStamp(content, null);
		} catch (Exception ex) {
			throw new SignerException(ex.getMessage());
		}
	}

	@Override
	public byte[] doTimeStampFromHashContent(byte[] hash) {
		try {
			return this.doTimeStamp(null, hash);
		} catch (Exception ex) {
			throw new SignerException(ex.getMessage());
		}
	}

	private byte[] doTimeStamp(byte[] content, byte[] hash) {
		try {
			AttributeFactory attributeFactory = AttributeFactory.getInstance();

			SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
				.factory(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
					.getId());
			if (content != null) {
				signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(),
					this.getCertificateChain(), content, signaturePolicy, null);
			} else {
				signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(),
					this.getCertificateChain(), null, signaturePolicy, hash);
			}
			byte[] result = signedOrUnsignedAttribute.getValue().getEncoded();
			return result;
		} catch (IOException ex) {
			throw new SignerException(ex.getMessage());
		}
	}

	@Override
	public List<Timestamp> checkTimeStampOnSignature(byte[] signature) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			List<Timestamp> listOfTimeStamp = new ArrayList<Timestamp>();
			CMSSignedData cmsSignedData = new CMSSignedData(signature);
			SignerInformationStore signers = cmsSignedData.getSignerInfos();
			Iterator<?> it = signers.getSigners().iterator();
			while (it.hasNext()) {
				SignerInformation signer = (SignerInformation) it.next();
				AttributeTable unsignedAttributes = signer
					.getUnsignedAttributes();
				Attribute attributeTimeStamp = unsignedAttributes
					.get(new ASN1ObjectIdentifier(
						PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
							.getId()));
				if (attributeTimeStamp != null) {
					TimeStampOperator timeStampOperator = new TimeStampOperator();
					byte[] varTimeStamp = attributeTimeStamp.getAttrValues()
						.getObjectAt(0).toASN1Primitive().getEncoded();
					TimeStampToken timeStampToken = new TimeStampToken(
						new CMSSignedData(varTimeStamp));
					Timestamp timeStampSigner = new Timestamp(timeStampToken);
					timeStampOperator.validate(signer.getSignature(),
						varTimeStamp, null);
					listOfTimeStamp.add(timeStampSigner);
				}
			}
			return listOfTimeStamp;
		} catch (CertificateCoreException | IOException | TSPException
			| CMSException e) {
			throw new SignerException(e);
		}
	}

	@Override
	public Timestamp checkTimeStampWithContent(byte[] timeStamp, byte[] content) {
		try {
			return this.checkTimeStamp(timeStamp, content, null);
		} catch (CertificateCoreException e) {
			throw new SignerException(e);
		}
	}

	@Override
	public Timestamp checkTimeStampWithHash(byte[] timeStamp, byte[] hash) {
		try {
			return this.checkTimeStamp(timeStamp, null, hash);
		} catch (CertificateCoreException e) {
			throw new SignerException(e);
		}
	}


	private Timestamp checkTimeStamp(byte[] timeStamp, byte[] content, byte[] hash) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			ais = new ASN1InputStream(new ByteArrayInputStream(timeStamp));
			ASN1Sequence seq = (ASN1Sequence) ais.readObject();
			Attribute attributeTimeStamp = new Attribute((ASN1ObjectIdentifier) seq.getObjectAt(0), (ASN1Set) seq.getObjectAt(1));
			byte[] varTimeStamp = attributeTimeStamp.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded();
			TimeStampOperator timeStampOperator = new TimeStampOperator();
			if (content != null) {
				timeStampOperator.validate(content, varTimeStamp, null);
			} else {
				timeStampOperator.validate(null, varTimeStamp, hash);
			}
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(varTimeStamp));
			Timestamp timeStampSigner = new Timestamp(timeStampToken);
			return timeStampSigner;
		} catch (CertificateCoreException | IOException | TSPException
			| CMSException e) {
			throw new SignerException(e);
		}

	}

	@Override
	public void setSignaturePolicy(PolicyFactory.Policies signaturePolicy) {
		PolicyFactory policyFactory = PolicyFactory.getInstance();
		org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy sp = policyFactory
			.loadPolicy(signaturePolicy);
		this.signaturePolicy = sp;
	}

	@Override
	public void setCertificates(Certificate[] certificates) {
		this.setCertificateChain(certificates);
	}

	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(Certificate certificateChain[]) {
		this.certificateChain = certificateChain;
	}

	@Override
	public void setPrivateKey(PrivateKey privateKey) {
		this.pkcs1.setPrivateKey(privateKey);
	}

}
