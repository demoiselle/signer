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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgAndLength;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgorithmIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.CertificateTrustPoint;
import org.demoiselle.signer.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.asn1.icpb.v2.PolicyValidator;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS1Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs1.PKCS1Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.SignedOrUnsignedAttribute;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.factory.AttributeFactory;
import org.demoiselle.signer.policy.impl.cades.util.AlgorithmNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Basic Implementation for digital signatures in PKCS7 Format.
 */
public class CAdESSigner implements PKCS7Signer {

	private static final Logger logger = LoggerFactory.getLogger(CAdESSigner.class);

	private final PKCS1Signer pkcs1 = PKCS1Factory.getInstance().factoryDefault();
	private X509Certificate certificate;
	private Certificate certificateChain[] = null;
	private Certificate certificateChainTimeStamp[] = null;
	private boolean attached = false;
	private SignaturePolicy signaturePolicy = null;
	private boolean defaultCertificateValidators = true;
	private static MessagesBundle cadesMessagesBundle = new MessagesBundle();
	private byte[] hash = null;
	private String policyName;
	private CertificateManager certificateManager;
	private byte[] escTimeStampContent;
	private boolean pades = false;
	private Date notAfterSignerCertificate;
	private String signatory;

	public CAdESSigner() {
		this.pkcs1.setAlgorithm((String) null);
		this.setSignaturePolicy(Policies.AD_RB_CADES_2_3);
	}

	public CAdESSigner(String algorithm, Policies police) {
		this.pkcs1.setAlgorithm(algorithm);
		this.setSignaturePolicy(police);
	}

	public CAdESSigner(String algorithm, Policies police, boolean pades) {
		this.pkcs1.setAlgorithm(algorithm);
		this.setSignaturePolicy(police);
		this.setPades(pades);
	}

	/**
	 * @return org.bouncycastle.cert.jcajce.JcaCertStore
	 */
	public Store<?> generatedCertStore(Certificate[] previewCerts) {
		Store<?> result = null;
		try {
			List<Certificate> certificates = new ArrayList<>();
			certificates.addAll(Arrays.asList(previewCerts));
			boolean add = true;

			for (Certificate cert : previewCerts)
				if (cert.equals(certificateChain[0]))
					add = false;

			if (add) {
				logger.debug("Adicionando Certificado no CertStore");
				certificates.addAll(Arrays.asList(certificateChain[0]));
			} else {
				logger.debug("Certificado já assinou este arquivo. Não adicionar no CertStore");
			}

			// CollectionCertStoreParameters cert = new
			// CollectionCertStoreParameters(certificates);
			result = new JcaCertStore(certificates);

		} catch (CertificateEncodingException ex) {
			throw new SignerException(ex);
		}
		return result;
	}

	@Override
	public String getAlgorithm() {
		return this.pkcs1.getAlgorithm();
	}

	@Override
	public PrivateKey getPrivateKey() {
		return this.pkcs1.getPrivateKey();
	}

	@Override
	public Provider getProvider() {
		return this.pkcs1.getProvider();
	}

	@Override
	public PublicKey getPublicKey() {
		return this.pkcs1.getPublicKey();
	}

	public byte[] getHash() {
		return hash;
	}

	public void setHash(byte[] hash) {
		this.hash = hash;
	}

	public boolean isDefaultCertificateValidators() {
		return this.defaultCertificateValidators;
	}

	@Override
	public void setAlgorithm(SignerAlgorithmEnum algorithm) {
		this.pkcs1.setAlgorithm(algorithm);
	}

	@Override
	public void setAlgorithm(String algorithm) {
		this.pkcs1.setAlgorithm(algorithm);
	}

	public boolean isAttached() {
		return attached;
	}

	public void setAttached(boolean attached) {
		this.attached = attached;
	}

	@Override
	public void setCertificates(Certificate[] certificates) {
		this.certificateChain = certificates;
	}

	public void setDefaultCertificateValidators(boolean defaultCertificateValidators) {
		this.defaultCertificateValidators = defaultCertificateValidators;
	}

	@Override
	public void setPrivateKey(PrivateKey privateKey) {
		this.pkcs1.setPrivateKey(privateKey);
	}

	@Override
	public void setProvider(Provider provider) {
		this.pkcs1.setProvider(provider);
	}

	@Override
	public void setPublicKey(PublicKey publicKey) {
		this.pkcs1.setPublicKey(publicKey);
	}

	/**
	 * Method of data signature and generation of the PKCS7 package. Signs only with
	 * content of type DATA: OID ContentType 1.2.840.113549.1.9.3 = OID Data
	 * 1.2.840.113549.1.7.1 It uses the algorithm set in the algorithm property, and
	 * if this property is not informed the algorithm of the
	 * {@link SignerAlgorithmEnum#DEFAULT} enumeration will be used. For this method
	 * it is necessary to inform the content, the private key and a digital
	 * certificate in the ICP-Brasil (PKI) standard.
	 *
	 * @param content Content to be signed.
	 */

	private byte[] doSign(byte[] content) {
		return this.doSign(content, null);
	}

	private Collection<X509Certificate> getSignersCertificates(CMSSignedData previewSignerData) {
		Collection<X509Certificate> result = new HashSet<X509Certificate>();
		Store<?> certStore = previewSignerData.getCertificates();
		SignerInformationStore signers = previewSignerData.getSignerInfos();
		Iterator<?> it = signers.getSigners().iterator();
		while (it.hasNext()) {
			SignerInformation signer = (SignerInformation) it.next();
			@SuppressWarnings("unchecked")
			Collection<?> certCollection = certStore.getMatches(signer.getSID());
			Iterator<?> certIt = certCollection.iterator();
			X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
			try {
				result.add(new JcaX509CertificateConverter().getCertificate(certificateHolder));
			} catch (CertificateException error) {
			}
		}
		return result;
	}

	private byte[] doSign(byte[] content, byte[] previewSignature) {

		Security.addProvider(new BouncyCastleProvider());
		if (this.certificateChain == null) {
			logger.error(cadesMessagesBundle.getString("error.certificate.null"));
			throw new SignerException(cadesMessagesBundle.getString("error.certificate.null"));
		}

		if (getPrivateKey() == null) {
			logger.error(cadesMessagesBundle.getString("error.privatekey.null"));
			throw new SignerException(cadesMessagesBundle.getString("error.privatekey.null"));
		}

		// Completa os certificados ausentes da cadeia, se houver
		if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
			this.certificate = (X509Certificate) this.certificateChain[0];
		}

		this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);

		if (this.certificateChain.length < 3) {
			throw new SignerException(cadesMessagesBundle.getString("error.no.ca", this.certificate.getIssuerDN()));
		}

		Certificate[] certStore = new Certificate[] {};

		CMSSignedData cmsPreviewSignedData = null;
		// Caso seja co-assinatura ou contra-assinatura
		// Importar todos os certificados da assinatura anterior
		if (previewSignature != null && previewSignature.length > 0) {
			try {
				cmsPreviewSignedData = new CMSSignedData(new CMSAbsentContent(), previewSignature);
			} catch (CMSException e) {
				logger.error(e.getMessage());
				throw new SignerException(e);
			}
			Collection<X509Certificate> previewCerts = this.getSignersCertificates(cmsPreviewSignedData);
			// previewCerts.add(this.certificate);
			certStore = previewCerts.toArray(new Certificate[] {});
		}
		try {
			setCertificateManager(new CertificateManager(this.certificate));
		} catch (CertificateValidatorCRLException cvre) {
			logger.warn(cvre.getMessage());
			ConfigurationRepo config = ConfigurationRepo.getInstance();
			config.setOnline(true);
			try {
				setCertificateManager(new CertificateManager(this.certificate));
			} catch (CertificateValidatorCRLException cvre1) {
				logger.error(cvre1.getMessage());
				throw new CertificateValidatorCRLException(cvre1.getMessage());
			}
		}

		AlgAndLength algAndLength = prepareAlgAndLength();

		AttributeFactory attributeFactory = AttributeFactory.getInstance();

		// Consulta e adiciona os atributos assinados
		ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

		// logger.info(cadesMessagesBundle.getString("info.signed.attribute"));
		if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers() != null) {
			for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr()
					.getObjectIdentifiers()) {

				SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
						.factory(objectIdentifier.getValue());
				signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(), certificateChain, content,
						signaturePolicy, this.hash);
				signedAttributes.add(signedOrUnsignedAttribute.getValue());
			}
		}

		// Monta a tabela de atributos assinados
		AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);

		// Create the table table generator that will added to the Signer
		// builder
		CMSAttributeTableGenerator signedAttributeGenerator;
		if (this.isPades()) {
			signedAttributeGenerator = new SimpleAttributeTableGenerator(signedAttributesTable);
		} else {
			signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);
		}

		validateCertificatesAndPolicy();

		// Realiza a assinatura do conteudo
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		try {
			gen.addCertificates(this.generatedCertStore(certStore));
		} catch (CMSException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		String algorithmOID = algAndLength.getAlgID().getValue();

		logger.debug(cadesMessagesBundle.getString("info.algorithm.id", algorithmOID));
		SignerInfoGenerator signerInfoGenerator;
		try {
			signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
					.setSignedAttributeGenerator(signedAttributeGenerator).setUnsignedAttributeGenerator(null)
					.build(AlgorithmNames.getAlgorithmNameByOID(algorithmOID), this.pkcs1.getPrivateKey(),
							this.certificate);
		} catch (CertificateEncodingException | OperatorCreationException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		gen.addSignerInfoGenerator(signerInfoGenerator);

		CMSTypedData cmsTypedData;
		// para assinatura do hash, content nulo
		if (content == null) {
			cmsTypedData = new CMSAbsentContent();
		} else {
			cmsTypedData = new CMSProcessableByteArray(content);
		}

		// Efetua a assinatura digital do conteúdo
		CMSSignedData cmsSignedData;
		try {
			cmsSignedData = gen.generate(cmsTypedData, this.attached);
		} catch (CMSException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		setAttached(false);

		// Consulta e adiciona os atributos não assinados//

		ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();

		logger.debug(cadesMessagesBundle.getString("info.unsigned.attribute"));
		Collection<SignerInformation> vNewSigners = cmsSignedData.getSignerInfos().getSigners();

		Iterator<SignerInformation> it = vNewSigners.iterator();
		SignerInformation oSi = it.next();

		if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
			for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr()
					.getObjectIdentifiers()) {
				SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
						.factory(objectIdentifier.getValue());

				switch (signedOrUnsignedAttribute.getOID()) {
				// PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
				case "1.2.840.113549.1.9.16.2.14":
					logger.debug("TimeStampToken");
					PrivateKey pkForTimeStamp = this.pkcs1.getPrivateKeyForTimeStamp();
					if (pkForTimeStamp == null) {
						pkForTimeStamp = this.pkcs1.getPrivateKey();
					}
					Certificate varCertificateChainTimeStamp[] = this.certificateChainTimeStamp;

					if (varCertificateChainTimeStamp == null || varCertificateChainTimeStamp.length < 1) {
						varCertificateChainTimeStamp = this.certificateChain;
					} else {
						varCertificateChainTimeStamp = CAManager.getInstance()
								.getCertificateChainArray((X509Certificate) varCertificateChainTimeStamp[0]);
					}
					signedOrUnsignedAttribute.initialize(pkForTimeStamp, varCertificateChainTimeStamp,
							oSi.getSignature(), signaturePolicy, this.hash);

					break;
				// PKCSObjectIdentifiers.id_aa_ets_escTimeStamp
				case "1.2.840.113549.1.9.16.2.25":
					logger.debug("ets_escTimeStamp");
					ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
					try {
						outputStream.write(oSi.getSignature());
						AttributeTable varUnsignedAttributes = oSi.getUnsignedAttributes();
						Attribute varAttribute = varUnsignedAttributes.get(
								new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId()));
						outputStream.write(varAttribute.getAttrType().getEncoded());
						outputStream.write(varAttribute.getAttrValues().getEncoded());
						varAttribute = varUnsignedAttributes
								.get(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId()));
						outputStream.write(varAttribute.getAttrType().getEncoded());
						outputStream.write(varAttribute.getAttrValues().getEncoded());
						varAttribute = varUnsignedAttributes
								.get(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId()));
						outputStream.write(varAttribute.getAttrType().getEncoded());
						outputStream.write(varAttribute.getAttrValues().getEncoded());
						escTimeStampContent = outputStream.toByteArray();
						PrivateKey pkForEscTimeStamp = this.pkcs1.getPrivateKeyForTimeStamp();
						if (pkForEscTimeStamp == null) {
							pkForEscTimeStamp = this.pkcs1.getPrivateKey();
						}
						Certificate varCertificateChainEscTimeStamp[] = this.certificateChainTimeStamp;
						if (varCertificateChainEscTimeStamp == null || varCertificateChainEscTimeStamp.length < 1) {
							varCertificateChainEscTimeStamp = this.certificateChain;
						} else {
							varCertificateChainEscTimeStamp = CAManager.getInstance()
									.getCertificateChainArray((X509Certificate) varCertificateChainEscTimeStamp[0]);
						}
						signedOrUnsignedAttribute.initialize(pkForEscTimeStamp, varCertificateChainEscTimeStamp,
								escTimeStampContent, signaturePolicy, this.hash);
						break;

					} catch (IOException e) {
						logger.error(e.getMessage());
						throw new SignerException(e);
					}
				default:
					signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(), certificateChain,
							oSi.getSignature(), signaturePolicy, this.hash);
				}
				unsignedAttributes.add(signedOrUnsignedAttribute.getValue());
				AttributeTable unsignedAttributesTable = new AttributeTable(unsignedAttributes);
				vNewSigners.remove(oSi);
				oSi = SignerInformation.replaceUnsignedAttributes(oSi, unsignedAttributesTable);
				vNewSigners.add(oSi);
			}
		}

		// TODO Estudar este método de contra-assinatura posteriormente
		if (previewSignature != null && previewSignature.length > 0) {
			vNewSigners.addAll(cmsPreviewSignedData.getSignerInfos().getSigners());
		}
		SignerInformationStore oNewSignerInformationStore = new SignerInformationStore(vNewSigners);
		CMSSignedData oSignedData = cmsSignedData;
		cmsSignedData = CMSSignedData.replaceSigners(oSignedData, oNewSignerInformationStore);

		byte[] result;
		try {
			result = cmsSignedData.getEncoded();
		} catch (IOException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		String SN = certificate.getSerialNumber().toString() + "("
				+ certificate.getSerialNumber().toString(16).toUpperCase() + ")";
		logger.debug(cadesMessagesBundle.getString("info.signed.by",
				certificate.getSubjectDN().toString().split(",")[0], SN));
		setSignatory(certificate.getSubjectDN().toString().split(",")[0] + " " + SN);
		PeriodValidator pV = new PeriodValidator();
		setNotAfterSignerCertificate(pV.valDate(this.certificate));
		return result;

	}

	@Override
	public void setSignaturePolicy(PolicyFactory.Policies signaturePolicy) {
		this.setPolicyName(signaturePolicy.name());
		PolicyFactory policyFactory = PolicyFactory.getInstance();
		org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy sp = policyFactory.loadPolicy(signaturePolicy);
		this.signaturePolicy = sp;
	}

	@Override
	public byte[] doAttachedSign(byte[] content) {
		this.setAttached(true);
		return this.doSign(content);
	}

	@Override
	public byte[] doDetachedSign(byte[] content) {
		return this.doSign(content);
	}

	@Override
	public byte[] doAttachedSign(byte[] content, byte[] previewSigned) {
		this.setAttached(true);
		return this.doSign(content, previewSigned);
	}

	@Override
	public byte[] doDetachedSign(byte[] content, byte[] previewSigned) {
		return this.doSign(content, previewSigned);
	}

	@SuppressWarnings("static-access")
	private CMSSignedData updateWithCounterSignature(final CMSSignedData counterSignature,
			final CMSSignedData originalSignature, SignerId selector) {

		// Retrieve the SignerInformation from the countersigned signature
		final SignerInformationStore originalSignerInfos = originalSignature.getSignerInfos();
		// Retrieve the SignerInformation from the countersignature
		final SignerInformationStore signerInfos = counterSignature.getSignerInfos();

		// Add the countersignature
		SignerInformation updatedSI = originalSignature.getSignerInfos().get(selector)
				.addCounterSigners(originalSignerInfos.get(selector), signerInfos);

		// Create updated SignerInformationStore
		Collection<SignerInformation> counterSignatureInformationCollection = new ArrayList<SignerInformation>();
		counterSignatureInformationCollection.add(updatedSI);
		SignerInformationStore signerInformationStore = new SignerInformationStore(
				counterSignatureInformationCollection);

		// Return new, updated signature
		return CMSSignedData.replaceSigners(originalSignature, signerInformationStore);
	}

	@Override
	public byte[] doCounterSign(byte[] previewCMSSignature) {
		try {
			Security.addProvider(new BouncyCastleProvider());

			// Reading a P7S file that is preview signature.
			CMSSignedData cmsPreviewSignedData = new CMSSignedData(previewCMSSignature);

			// Build BouncyCastle object that is a set of signatures
			Collection<SignerInformation> previewSigners = cmsPreviewSignedData.getSignerInfos().getSigners();

			for (SignerInformation previewSigner : previewSigners) {
				// build a counter-signature per previewSignature
				byte[] previewSignatureFromSigner = previewSigner.getSignature();
				CMSSignedData cmsCounterSignedData = new CMSSignedData(this.doSign(previewSignatureFromSigner));
				cmsPreviewSignedData = this.updateWithCounterSignature(cmsCounterSignedData, cmsPreviewSignedData,
						previewSigner.getSID());
			}
			return cmsPreviewSignedData.getEncoded();
		} catch (Throwable error) {
			throw new SignerException(error);
		}
	}

	@Override
	public byte[] doHashSign(byte[] hash) {
		this.hash = hash;
		return this.doSign(null);
	}

	@Override
	public byte[] doHashCoSign(byte[] hash, byte[] previewSigned) {
		this.hash = hash;
		return this.doSign(null, previewSigned);
	}

	public String getPolicyName() {
		return policyName;
	}

	public void setPolicyName(String policyName) {
		this.policyName = policyName;
	}

	public CertificateManager getCertificateManager() {
		return certificateManager;
	}

	public void setCertificateManager(CertificateManager certificateManager) {
		this.certificateManager = certificateManager;
	}

	public boolean isPades() {
		return pades;
	}

	public void setPades(boolean pades) {
		this.pades = pades;
	}

	/**
	 * @return the notAfterSignerCertificate
	 */
	@Override
	public Date getNotAfterSignerCertificate() {
		return notAfterSignerCertificate;
	}

	/**
	 * @param notAfterSignerCertificate the notAfterSignerCertificate to set
	 */
	public void setNotAfterSignerCertificate(Date notAfterSignerCertificate) {
		this.notAfterSignerCertificate = notAfterSignerCertificate;
	}

	@Override
	public void setCertificatesForTimeStamp(Certificate[] certificates) {
		this.certificateChainTimeStamp = certificates;
	}

	/**
	 * the private key to use for request timestamp
	 */
	@Override
	public void setPrivateKeyForTimeStamp(PrivateKey privateKeyForTimeStamp) {
		this.pkcs1.setPrivateKeyForTimeStamp(privateKeyForTimeStamp);
	}

	@Override
	public PrivateKey getPrivateKeyForTimeStamp() {
		return this.pkcs1.getPrivateKeyForTimeStamp();
	}

	/**
	 * @return who perform the signature
	 */
	@Override
	public String getSignatory() {
		return signatory;
	}

	public void setSignatory(String signatory) {
		this.signatory = signatory;
	}

	@Override
	public CMSSignedData prepareDetachedSign(byte[] content) {
		return prepareSignature(content, null);
	}

	@Override
	public CMSSignedData prepareAttachedSign(byte[] content) {
		this.setAttached(true);
		return prepareSignature(content, null);
	}

	@Override
	public CMSSignedData prepareHashSign(byte[] hash) {

		this.hash = hash;
		return prepareSignature(null, null);
	}

	@Override
	public byte[] envelopDetachedSign(CMSSignedData signedData) {
		return envelopSignature(signedData, null);
	}

	@Override
	public byte[] envelopAttachedSign(CMSSignedData signedData) {
		return envelopSignature(signedData, null);
	}

	@Override
	public byte[] envelopHashSign(CMSSignedData signedData) {
		return envelopSignature(signedData, null);
	}

	/**
	 * generate signed attributes
	 * 
	 * @param content
	 * @return
	 */
	private CMSSignedData prepareSignature(byte[] content, byte[] previewSignature) {
		AttributeTable signedAttributesTable = prepareSignedAttributes(content, previewSignature);

		validateCertificatesAndPolicy();

		if (getPrivateKey() == null) {
			logger.error(cadesMessagesBundle.getString("error.privatekey.null"));
			throw new SignerException(cadesMessagesBundle.getString("error.privatekey.null"));
		}

		// Realiza a assinatura do conteudo
		CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
		Certificate[] certStore = extractCertificates(previewSignature);
		try {
			gen.addCertificates(this.generatedCertStore(certStore));
		} catch (CMSException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		String algorithmOID = prepareAlgAndLength().getAlgID().getValue();

		// Create the table table generator that will added to the Signer
		// builder
		CMSAttributeTableGenerator signedAttributeGenerator;
		if (this.isPades()) {
			signedAttributeGenerator = new SimpleAttributeTableGenerator(signedAttributesTable);
		} else {
			signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(signedAttributesTable);
		}

		logger.debug(cadesMessagesBundle.getString("info.algorithm.id", algorithmOID));
		SignerInfoGenerator signerInfoGenerator;
		try {
			signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
					.setSignedAttributeGenerator(signedAttributeGenerator).setUnsignedAttributeGenerator(null)
					.build(AlgorithmNames.getAlgorithmNameByOID(algorithmOID), this.pkcs1.getPrivateKey(),
							this.certificate);
		} catch (CertificateEncodingException | OperatorCreationException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		gen.addSignerInfoGenerator(signerInfoGenerator);

		CMSTypedData cmsTypedData;
		// para assinatura do hash, content nulo
		if (content == null) {
			cmsTypedData = new CMSAbsentContent();
		} else {
			cmsTypedData = new CMSProcessableByteArray(content);
		}

		// Efetua a assinatura digital do conteúdo
		CMSSignedData cmsSignedData;
		try {
			cmsSignedData = gen.generate(cmsTypedData, this.attached);
		} catch (CMSException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		setAttached(false);
		return cmsSignedData;
	}

	public byte[] envelopSignature(CMSSignedData cmsSignedData, byte[] previewSignature) {

		
		checkCertificateChain();
		// Consulta e adiciona os atributos não assinados//

		AttributeFactory attributeFactory = AttributeFactory.getInstance();
		ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();

		logger.debug(cadesMessagesBundle.getString("info.unsigned.attribute"));
		Collection<SignerInformation> vNewSigners = cmsSignedData.getSignerInfos().getSigners();

		Iterator<SignerInformation> it = vNewSigners.iterator();
		SignerInformation oSi = it.next();

		if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
			for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr()
					.getObjectIdentifiers()) {
				SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
						.factory(objectIdentifier.getValue());

				switch (signedOrUnsignedAttribute.getOID()) {
				// PKCSObjectIdentifiers.id_aa_signatureTimeStampToken
				case "1.2.840.113549.1.9.16.2.14":
					logger.debug("TimeStampToken");
					PrivateKey pkForTimeStamp = this.pkcs1.getPrivateKeyForTimeStamp();
					if (pkForTimeStamp == null) {
						pkForTimeStamp = this.pkcs1.getPrivateKey();
					}
					Certificate varCertificateChainTimeStamp[] = this.certificateChainTimeStamp;

					if (varCertificateChainTimeStamp == null || varCertificateChainTimeStamp.length < 1) {
						varCertificateChainTimeStamp = this.certificateChain;
					} else {
						varCertificateChainTimeStamp = CAManager.getInstance()
								.getCertificateChainArray((X509Certificate) varCertificateChainTimeStamp[0]);
					}
					signedOrUnsignedAttribute.initialize(pkForTimeStamp, varCertificateChainTimeStamp,
							oSi.getSignature(), signaturePolicy, this.hash);

					break;
				// PKCSObjectIdentifiers.id_aa_ets_escTimeStamp
				case "1.2.840.113549.1.9.16.2.25":
					logger.debug("ets_escTimeStamp");
					ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
					try {
						outputStream.write(oSi.getSignature());
						AttributeTable varUnsignedAttributes = oSi.getUnsignedAttributes();
						Attribute varAttribute = varUnsignedAttributes.get(
								new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId()));
						outputStream.write(varAttribute.getAttrType().getEncoded());
						outputStream.write(varAttribute.getAttrValues().getEncoded());
						varAttribute = varUnsignedAttributes
								.get(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId()));
						outputStream.write(varAttribute.getAttrType().getEncoded());
						outputStream.write(varAttribute.getAttrValues().getEncoded());
						varAttribute = varUnsignedAttributes
								.get(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId()));
						outputStream.write(varAttribute.getAttrType().getEncoded());
						outputStream.write(varAttribute.getAttrValues().getEncoded());
						escTimeStampContent = outputStream.toByteArray();
						PrivateKey pkForEscTimeStamp = this.pkcs1.getPrivateKeyForTimeStamp();
						if (pkForEscTimeStamp == null) {
							pkForEscTimeStamp = this.pkcs1.getPrivateKey();
						}
						Certificate varCertificateChainEscTimeStamp[] = this.certificateChainTimeStamp;
						if (varCertificateChainEscTimeStamp == null || varCertificateChainEscTimeStamp.length < 1) {
							varCertificateChainEscTimeStamp = this.certificateChain;
						} else {
							varCertificateChainEscTimeStamp = CAManager.getInstance()
									.getCertificateChainArray((X509Certificate) varCertificateChainEscTimeStamp[0]);
						}
						signedOrUnsignedAttribute.initialize(pkForEscTimeStamp, varCertificateChainEscTimeStamp,
								escTimeStampContent, signaturePolicy, this.hash);
						break;

					} catch (IOException e) {
						logger.error(e.getMessage());
						throw new SignerException(e);
					}
				default:
					signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(), certificateChain,
							oSi.getSignature(), signaturePolicy, this.hash);
				}
				unsignedAttributes.add(signedOrUnsignedAttribute.getValue());
				AttributeTable unsignedAttributesTable = new AttributeTable(unsignedAttributes);
				vNewSigners.remove(oSi);
				oSi = SignerInformation.replaceUnsignedAttributes(oSi, unsignedAttributesTable);
				vNewSigners.add(oSi);
			}
		}

		CMSSignedData cmsPreviewSignedData = null;
		// Caso seja co-assinatura ou contra-assinatura
		// Importar todos os certificados da assinatura anterior
		if (previewSignature != null && previewSignature.length > 0) {
			try {
				cmsPreviewSignedData = new CMSSignedData(new CMSAbsentContent(), previewSignature);
			} catch (CMSException e) {
				logger.error(e.getMessage());
				throw new SignerException(e);
			}
		}

		// TODO Estudar este método de contra-assinatura posteriormente
		if (previewSignature != null && previewSignature.length > 0) {
			vNewSigners.addAll(cmsPreviewSignedData.getSignerInfos().getSigners());
		}
		SignerInformationStore oNewSignerInformationStore = new SignerInformationStore(vNewSigners);
		CMSSignedData oSignedData = cmsSignedData;
		cmsSignedData = CMSSignedData.replaceSigners(oSignedData, oNewSignerInformationStore);

		byte[] result;
		try {
			result = cmsSignedData.getEncoded();
		} catch (IOException e) {
			logger.error(e.getMessage());
			throw new SignerException(e);
		}
		String SN = certificate.getSerialNumber().toString() + "("
				+ certificate.getSerialNumber().toString(16).toUpperCase() + ")";
		logger.debug(cadesMessagesBundle.getString("info.signed.by",
				certificate.getSubjectDN().toString().split(",")[0], SN));
		setSignatory(certificate.getSubjectDN().toString().split(",")[0] + " " + SN);
		PeriodValidator pV = new PeriodValidator();
		setNotAfterSignerCertificate(pV.valDate(this.certificate));
		return result;
	}

	/**
	 * Recebe o conteúdo e uma assinatura prévia e prepara a tabela de atributos
	 * assináveis. Caso o conteúdo seja nulo, o hash do documento a ser assinado
	 * deve ser informado na propriedade this.hash. A tabela de atributos retornada
	 * ainda precisará receber o atributo signingTime e ser reordenada antes que
	 * possa ser realizada a assinatura.
	 * 
	 * @param content          Conteúdo que está sendo assinado, ou null
	 * @param previewSignature Assinatura prévia do mesmo conteúdo, para copiar os
	 *                         certificados
	 * @return
	 */
	public AttributeTable prepareSignedAttributes(byte[] content, byte[] previewSignature) {
		
		checkCertificateChain();

		// AlgAndLength algAndLength = prepareAlgAndLength();

		AttributeFactory attributeFactory = AttributeFactory.getInstance();

		// Consulta e adiciona os atributos assinados
		ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

		// logger.info(cadesMessagesBundle.getString("info.signed.attribute"));
		if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
				.getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers() != null) {
			for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr()
					.getObjectIdentifiers()) {

				SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
						.factory(objectIdentifier.getValue());
				signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(), certificateChain, content,
						signaturePolicy, this.getHash());
				signedAttributes.add(signedOrUnsignedAttribute.getValue());
			}
		}

		// Monta a tabela de atributos assinados
		AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);

		return signedAttributesTable;
	}

	/**
	 * Seleciona os algorítmos de hash e criptografia e também o tamanho mínimo da
	 * chave que será utilizada para realizar a assinatura.
	 * 
	 * @return
	 */
	public AlgAndLength prepareAlgAndLength() {
		// Recupera a lista de algoritmos da politica e o tamanho minimo da
		// chave
		List<AlgAndLength> listOfAlgAndLength = new ArrayList<AlgAndLength>();

		for (AlgAndLength algLength : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules().getAlgorithmConstraintSet().getSignerAlgorithmConstraints().getAlgAndLengths()) {
			listOfAlgAndLength.add(algLength);
		}
		AlgAndLength algAndLength = null;

		// caso o algoritmo tenha sido informado como parâmetro irá
		// verificar se o mesmo é permitido pela politica
		if (this.pkcs1.getAlgorithm() != null) {
			String varSetedAlgorithmOID = AlgorithmNames.getOIDByAlgorithmName(this.pkcs1.getAlgorithm());
			for (AlgAndLength algLength : listOfAlgAndLength) {
				if (algLength.getAlgID().getValue().equalsIgnoreCase(varSetedAlgorithmOID)) {
					algAndLength = algLength;
					SignerAlgorithmEnum varSignerAlgorithmEnum = SignerAlgorithmEnum.valueOf(this.pkcs1.getAlgorithm());
					String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
					ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
					varObjectIdentifier.setValue(varOIDAlgorithmHash);
					AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
					varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
					signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
				}
			}
		} else {
			algAndLength = listOfAlgAndLength.get(1);
			this.pkcs1.setAlgorithm(AlgorithmNames.getAlgorithmNameByOID(algAndLength.getAlgID().getValue()));
			SignerAlgorithmEnum varSignerAlgorithmEnum = SignerAlgorithmEnum.valueOf(this.pkcs1.getAlgorithm());
			String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
			ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
			varObjectIdentifier.setValue(varOIDAlgorithmHash);
			AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
			varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
			signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);

		}
		if (algAndLength == null) {
			throw new SignerException(cadesMessagesBundle.getString("error.no.algorithm.policy"));
		}
		logger.debug(cadesMessagesBundle.getString("info.algorithm.id", algAndLength.getAlgID().getValue()));
		logger.debug(cadesMessagesBundle.getString("info.algorithm.name",
				AlgorithmNames.getAlgorithmNameByOID(algAndLength.getAlgID().getValue())));
		logger.debug(cadesMessagesBundle.getString("info.min.key.length", algAndLength.getMinKeyLength()));
		// Recupera o tamanho minimo da chave para validacao
		logger.debug(cadesMessagesBundle.getString("info.validating.key.length"));
		int keyLegth = ((RSAKey) certificate.getPublicKey()).getModulus().bitLength();
		if (keyLegth < algAndLength.getMinKeyLength()) {
			throw new SignerException(cadesMessagesBundle.getString("error.min.key.length",
					algAndLength.getMinKeyLength().toString(), keyLegth));
		}
		return algAndLength;
	}

	/**
	 * Compõe a cadeia de confiança e a valida. Verifica, também, se a política está
	 * dentro do prazo de validade.
	 */
	private void validateCertificatesAndPolicy() {
		// Recupera o(s) certificado(s) de confianca para validacao
		Collection<X509Certificate> trustedCAs = new HashSet<X509Certificate>();

		Collection<CertificateTrustPoint> ctp = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules().getSigningCertTrustCondition().getSignerTrustTrees().getCertificateTrustPoints();
		for (CertificateTrustPoint certificateTrustPoint : ctp) {
			logger.debug(cadesMessagesBundle.getString("info.trust.point",
					certificateTrustPoint.getTrustpoint().getSubjectDN().toString()));
			trustedCAs.add(certificateTrustPoint.getTrustpoint());
		}

		// Efetua a validacao das cadeias do certificado baseado na politica
		Collection<X509Certificate> certificateChainTrusted = new HashSet<X509Certificate>();
		for (Certificate certCA : certificateChain) {
			certificateChainTrusted.add((X509Certificate) certCA);
		}
		X509Certificate rootOfCertificate = null;
		for (X509Certificate tcac : certificateChainTrusted) {
			logger.debug(tcac.getIssuerDN().toString());
			if (CAManager.getInstance().isRootCA(tcac)) {
				rootOfCertificate = tcac;
			}
		}
		if (trustedCAs.contains(rootOfCertificate)) {
			logger.debug(cadesMessagesBundle.getString("info.trust.in.point", rootOfCertificate.getSubjectDN()));
		} else {
			// Não encontrou na política, verificará nas cadeias do
			// componente chain-icp-brasil provavelmente certificado de
			// homologação.
			logger.debug(cadesMessagesBundle.getString("info.trust.poin.homolog"));
			CAManager.getInstance().validateRootCAs(certificateChainTrusted, certificate);
		}

		// validade da politica
		logger.debug(cadesMessagesBundle.getString("info.policy.valid.period"));
		PolicyValidator pv = new PolicyValidator(this.signaturePolicy, this.policyName);
		pv.validate();
	}

	/**
	 * Extrai a lista de certificados incluídos em um envelope PKCS#7 ou CMS
	 * 
	 * @param previewSignature
	 * @return
	 */
	public Certificate[] extractCertificates(byte[] previewSignature) {
		Certificate[] certStore = new Certificate[] {};

		CMSSignedData cmsPreviewSignedData = null;
		// Caso seja co-assinatura ou contra-assinatura
		// Importar todos os certificados da assinatura anterior
		if (previewSignature != null && previewSignature.length > 0) {
			try {
				cmsPreviewSignedData = new CMSSignedData(new CMSAbsentContent(), previewSignature);
			} catch (CMSException e) {
				logger.error(e.getMessage());
				throw new SignerException(e);
			}
			Collection<X509Certificate> previewCerts = this.getSignersCertificates(cmsPreviewSignedData);
			// previewCerts.add(this.certificate);
			certStore = previewCerts.toArray(new Certificate[] {});
		}
		return certStore;
	}

	void checkCertificateChain() {

		Security.addProvider(new BouncyCastleProvider());
		if (this.certificateChain == null) {
			logger.error(cadesMessagesBundle.getString("error.certificate.null"));
			throw new SignerException(cadesMessagesBundle.getString("error.certificate.null"));
		}

		// Completa os certificados ausentes da cadeia, se houver
		if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
			this.certificate = (X509Certificate) this.certificateChain[0];
		}

		this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);

		if (this.certificateChain.length < 3) {
			throw new SignerException(cadesMessagesBundle.getString("error.no.ca", this.certificate.getIssuerDN()));
		}

		try {
			setCertificateManager(new CertificateManager(this.certificate));
		} catch (CertificateValidatorCRLException cvre) {
			logger.warn(cvre.getMessage());
			ConfigurationRepo config = ConfigurationRepo.getInstance();
			config.setOnline(true);
			try {
				setCertificateManager(new CertificateManager(this.certificate));
			} catch (CertificateValidatorCRLException cvre1) {
				logger.error(cvre1.getMessage());
				throw new CertificateValidatorCRLException(cvre1.getMessage());
			}
		}
	}
}
