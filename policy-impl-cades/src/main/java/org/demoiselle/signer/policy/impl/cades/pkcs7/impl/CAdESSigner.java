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
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.ca.manager.CAManagerException;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgAndLength;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgorithmIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.CertificateTrustPoint;
import org.demoiselle.signer.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignatureInfo;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS1Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs1.PKCS1Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.SignedOrUnsignedAttribute;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.factory.AttributeFactory;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.connector.TimeStampOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * Basic Implementation for digital signatures in PKCS7 Format.
 * 
 */
public class CAdESSigner implements PKCS7Signer {

	private static final Logger logger = LoggerFactory.getLogger(CAdESSigner.class);

	private final PKCS1Signer pkcs1 = PKCS1Factory.getInstance().factoryDefault();
	private X509Certificate certificate;
	private Certificate certificateChain[];
	private boolean attached = false;
	private SignaturePolicy signaturePolicy = null;
	private boolean defaultCertificateValidators = true;
	private static MessagesBundle cadesMessagesBundle = new MessagesBundle();
	private byte[] hash = null;
	private Map hashes = new HashMap();
	private boolean checkHash = false;
	private List<SignatureInfo> signatureInfo = new ArrayList<SignatureInfo>();

	// private Collection<IValidator> certificateValidators = null;

	public CAdESSigner() {
		this.pkcs1.setAlgorithm((String) null);
		this.setSignaturePolicy(Policies.AD_RB_CADES_2_2);

	}

	public CAdESSigner(String algorithm, Policies police) {
		this.pkcs1.setAlgorithm(algorithm);
		this.setSignaturePolicy(police);

	}

	/**
	 * Validation is done only on digital signatures with a single signer. Valid
	 * only with content of type DATA.: OID ContentType 1.2.840.113549.1.9.3 =
	 * OID Data 1.2.840.113549.1.7.1
	 *
	 * @params content Is only necessary to inform if the PKCS7 package is NOT
	 *         ATTACHED type. If it is of type attached, this parameter will be
	 *         replaced by the contents of the PKCS7 package.
	 * @params signedData Value in bytes of the PKCS7 package, such as the
	 *         contents of a ".p7s" file. It is not only signature as in the
	 *         case of PKCS1.
	 */
	@SuppressWarnings("unchecked")
	// TODO: Implementar validação de co-assinaturas
	@Override
	public boolean check(byte[] content, byte[] signedData) throws SignerException{
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData cmsSignedData = null;
		try {
			if (content == null) {
				if (this.checkHash){
					cmsSignedData = new CMSSignedData(this.hashes, signedData);
					this.checkHash = false;
				}else{
					cmsSignedData = new CMSSignedData(signedData);
				}
				
			} else {
				cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(content), signedData);
			}
		} catch (CMSException ex) {
			throw new SignerException(cadesMessagesBundle.getString("error.invalid.bytes.pkcs7"), ex);
		}

		// Quantidade inicial de assinaturas validadas
		int verified = 0;

		Store<?> certStore = cmsSignedData.getCertificates();
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		Iterator<?> it = signers.getSigners().iterator();

		// Realização da verificação básica de todas as assinaturas
		while (it.hasNext()) {
			try {
				SignerInformation signer = (SignerInformation) it.next();
				SignerInformationStore s = signer.getCounterSignatures();
				SignatureInfo si = new SignatureInfo();
				logger.info("Foi(ram) encontrada(s) " + s.size() + " contra-assinatura(s).");

				Collection<?> certCollection = certStore.getMatches(signer.getSID());

				Iterator<?> certIt = certCollection.iterator();
				X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
						
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificateHolder))) {
					verified++;
					logger.info(cadesMessagesBundle.getString("info.signature.valid.seq", verified));

				}
				

				// Realiza a verificação dos atributos assinados
				logger.info(cadesMessagesBundle.getString("info.signed.attribute"));
				AttributeTable signedAttributes = signer.getSignedAttributes();
				if ((signedAttributes == null) || (signedAttributes != null && signedAttributes.size() == 0)) {
					throw new SignerException(cadesMessagesBundle.getString("error.signed.attribute.not.found"));
				}

				// Realiza a verificação dos atributos não assinados
				logger.info(cadesMessagesBundle.getString("info.unsigned.attribute"));
				AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
				if ((unsignedAttributes == null) || (unsignedAttributes != null && unsignedAttributes.size() == 0)) {
					logger.info(cadesMessagesBundle.getString("error.unsigned.attribute.not.found"));
				}

				
				// Mostra data e  hora da assinatura, não é carimbo de tempo
				Date dataHora = (((ASN1UTCTime) signedAttributes.get(CMSAttributes.signingTime).getAttrValues().getObjectAt(0)).getDate());
				logger.info(cadesMessagesBundle.getString("info.date.utc",dataHora));
				
				logger.info(cadesMessagesBundle.getString("info.attribute.validation"));
				// Valida o atributo ContentType
				Attribute attributeContentType = signedAttributes.get(CMSAttributes.contentType);
				if (attributeContentType == null) {
					throw new SignerException(
							cadesMessagesBundle.getString("error.pcks7.attribute.not.found", "ContentType"));
				}

				if (!attributeContentType.getAttrValues().getObjectAt(0).equals(ContentInfo.data)) {
					throw new SignerException(cadesMessagesBundle.getString("error.content.not.data"));
				}

				// Validando o atributo MessageDigest
				Attribute attributeMessageDigest = signedAttributes.get(CMSAttributes.messageDigest);
				if (attributeMessageDigest == null) {
					throw new SignerException(
							cadesMessagesBundle.getString("error.pcks7.attribute.not.found", "MessageDigest"));
				}
				
				// Validando o atributo Timestampo (carimbo de tempo) 
				Attribute attributeTimeStamp = unsignedAttributes.get(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId()));
				if (attributeTimeStamp != null){
					try {
						TimeStampOperator timeStampOperator = new TimeStampOperator();
						//byte [] varTimeStamp = attributeTimeStamp.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded("BER");
						byte [] varTimeStamp = attributeTimeStamp.getAttrValues().getObjectAt(0).toASN1Primitive().getEncoded();
						TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(varTimeStamp));
						Timestamp timeStampSigner = new Timestamp(timeStampToken);
						timeStampOperator.validate(signer.getSignature(),varTimeStamp , null);
						si.setTimeStampSigner(timeStampSigner);
					} catch (CertificateCoreException | IOException | TSPException e) {
						throw new SignerException(e);
					}
					
				}

				X509Certificate varCert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
				LinkedList<X509Certificate> varChain = (LinkedList<X509Certificate>) CAManager.getInstance().getCertificateChain(varCert);
				si.setSignDate(dataHora);
				si.setChain(varChain);
				this.getSignatureInfo().add(si);
				
			} catch (OperatorCreationException | java.security.cert.CertificateException ex) {
				throw new SignerException(ex);
			} catch (CMSException ex) {				
				// When file is mismatch with sign
				if (ex instanceof CMSSignerDigestMismatchException)
					throw new SignerException(cadesMessagesBundle.getString("error.signature.mismatch"), ex);
				else
					throw new SignerException(cadesMessagesBundle.getString("error.signature.invalid"), ex);
			} catch (ParseException e) {
				throw new SignerException(e);
			}
		}

		logger.info(cadesMessagesBundle.getString("info.signature.verified", verified));
		// TODO Efetuar o parsing da estrutura CMS
		return true;
	}

	/**
	 * 
	 * @return org.bouncycastle.cert.jcajce.JcaCertStore
	 */
	private Store<?> generatedCertStore() {
		Store<?> result = null;
		try {
			List<Certificate> certificates = new ArrayList<>();
			certificates.addAll(Arrays.asList(certificateChain));
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
		return this.signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue();
	}

	/**
	 * Return the signed file content attached to the signature.
	 *
	 * @param signed
	 *            Signature and signed content.
	 * @return
	 */
	public byte[] getAttached(byte[] signed) {
		return this.getAttached(signed, true);
	}

	/**
	 * Extracts the signed content from the digital signature structure, if it
	 * is a signature with attached content.
	 *
	 * @param signed
	 *            Signature and signed content.
	 * @param validateOnExtract
	 *            TRUE (to execute validation) or FALSE (not execute validation)
	 * 
	 * @return
	 */
	@Override
	public byte[] getAttached(byte[] signed, boolean validateOnExtract) {

		byte[] result = null;

		if (validateOnExtract) {
			this.check(null, signed);
		}

		CMSSignedData signedData = null;
		try {
			signedData = new CMSSignedData(signed);
		} catch (CMSException exception) {
			throw new SignerException(cadesMessagesBundle.getString("error.invalid.bytes.pkcs7"), exception);
		}

		try {
			CMSProcessable contentProcessable = signedData.getSignedContent();
			if (contentProcessable != null) {
				result = (byte[]) contentProcessable.getContent();
			}
		} catch (Exception exception) {
			throw new SignerException(cadesMessagesBundle.getString("error.get.content.pkcs7"), exception);
		}

		return result;

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

	private void setAttached(boolean attached) {
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
	 * Method of data signature and generation of the PKCS7 package. Signs only
	 * with content of type DATA: OID ContentType 1.2.840.113549.1.9.3 = OID
	 * Data 1.2.840.113549.1.7.1 It uses the algorithm set in the algorithm
	 * property, and if this property is not informed the algorithm of the
	 * {@link SignerAlgorithmEnum.DEFAULT} enumeration will be used. For this
	 * method it is necessary to inform the content, the private key and a
	 * digital certificate in the ICP-Brasil (PKI) standard.
	 *
	 * @param content
	 *            Content to be signed.
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
		try {
			Security.addProvider(new BouncyCastleProvider());

			// Completa os certificados ausentes da cadeia, se houver
			if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
				this.certificate = (X509Certificate) this.certificateChain[0];
			}

			if (this.certificateChain == null || this.certificateChain.length <= 1) {
				this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);
			}

			CMSSignedData cmsPreviewSignedData = null;
			// Caso seja co-assinatura ou contra-assinatura
			// Importar todos os certificados da assinatura anterior
			if (previewSignature != null && previewSignature.length > 0) {
				cmsPreviewSignedData = new CMSSignedData(new CMSAbsentContent(), previewSignature);
				Collection<X509Certificate> previewCerts = this.getSignersCertificates(cmsPreviewSignedData);
				for (Certificate cert : this.certificateChain) {
					previewCerts.add((X509Certificate) cert);
				}
				this.certificateChain = previewCerts.toArray(new Certificate[] {});
			}

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
						SignerAlgorithmEnum varSignerAlgorithmEnum = SignerAlgorithmEnum
								.valueOf(this.pkcs1.getAlgorithm());
						String varOIDAlgorithmHash = varSignerAlgorithmEnum.getOIDAlgorithmHash();
						ObjectIdentifier varObjectIdentifier = signaturePolicy.getSignPolicyHashAlg().getAlgorithm();
						varObjectIdentifier.setValue(varOIDAlgorithmHash);
						AlgorithmIdentifier varAlgorithmIdentifier = signaturePolicy.getSignPolicyHashAlg();
						varAlgorithmIdentifier.setAlgorithm(varObjectIdentifier);
						signaturePolicy.setSignPolicyHashAlg(varAlgorithmIdentifier);
					}
				}
			} else {
				algAndLength = listOfAlgAndLength.get(0);
			}
			if (algAndLength == null) {
				throw new SignerException(cadesMessagesBundle.getString("error.no.algorithm.policy"));
			}
			logger.info(cadesMessagesBundle.getString("info.algorithm.id", algAndLength.getAlgID().getValue()));
			logger.info(cadesMessagesBundle.getString("info.algorithm.name",
					AlgorithmNames.getAlgorithmNameByOID(algAndLength.getAlgID().getValue())));
			logger.info(cadesMessagesBundle.getString("info.algorithm.policy.default",
					AlgorithmNames.getOIDByAlgorithmName(getAlgorithm())));
			logger.info(cadesMessagesBundle.getString("info.min.key.length", algAndLength.getMinKeyLength()));

			// Recupera o tamanho minimo da chave para validacao
			logger.info(cadesMessagesBundle.getString("info.validating.key.length"));
			int keyLegth = ((RSAKey) certificate.getPublicKey()).getModulus().bitLength();
			if (keyLegth < algAndLength.getMinKeyLength()) {
				throw new SignerException(cadesMessagesBundle.getString("error.min.key.length",
						algAndLength.getMinKeyLength().toString(), keyLegth));
			}

			AttributeFactory attributeFactory = AttributeFactory.getInstance();

			// Consulta e adiciona os atributos assinados
			ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

			logger.info(cadesMessagesBundle.getString("info.signed.attribute"));
			if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr()
					.getObjectIdentifiers() != null) {
				for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo()
						.getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules()
						.getMandatedSignedAttr().getObjectIdentifiers()) {

					SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
							.factory(objectIdentifier.getValue());
					signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(), certificateChain, content,
							signaturePolicy, this.hash);
					signedAttributes.add(signedOrUnsignedAttribute.getValue());
				}
			}

			ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();
			
			// Monta a tabela de atributos assinados e não assinados
			AttributeTable signedAttributesTable = new AttributeTable(signedAttributes);
			AttributeTable unsignedAttributesTable = new AttributeTable(unsignedAttributes);
			

			// Create the table table generator that will added to the Signer
			// builder
			CMSAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(
					signedAttributesTable);
			CMSAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(
					unsignedAttributesTable);

			// Recupera o(s) certificado(s) de confianca para validacao
			Collection<X509Certificate> trustedCAs = new HashSet<X509Certificate>();

			Collection<CertificateTrustPoint> ctp = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSigningCertTrustCondition().getSignerTrustTrees().getCertificateTrustPoints();
			for (CertificateTrustPoint certificateTrustPoint : ctp) {
				logger.info(cadesMessagesBundle.getString("info.trust.point",
						certificateTrustPoint.getTrustpoint().getSubjectDN().toString()));
				trustedCAs.add(certificateTrustPoint.getTrustpoint());
			}

			// Efetua a validacao das cadeias do certificado baseado na politica
			try {
				CAManager.getInstance().validateRootCAs(trustedCAs, certificate);
			} catch (CAManagerException ex) {
				// Não encontrou na política, verificará nas cadeias do
				// componente chain-icp-brasil provavelmente certificado de
				// homologação.
				logger.info(cadesMessagesBundle.getString("info.trust.poin.homolog"));
				trustedCAs = CAManager.getInstance().getCertificateChain(certificate);
				CAManager.getInstance().validateRootCAs(trustedCAs, certificate);
			}

			// Recupera a data de validade da politica para validacao
			logger.info(cadesMessagesBundle.getString("info.policy.valid.period"));
			Date dateNotBefore = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()
					.getNotBefore().getDate();
			Date dateNotAfter = signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()
					.getNotAfter().getDate();

			Date actualDate = new GregorianCalendar().getTime();

			if (actualDate.before(dateNotBefore) || actualDate.after(dateNotAfter)) {
				SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy - hh:mm:ss");
				throw new SignerException(cadesMessagesBundle.getString("error.policy.valid.period",
						sdf.format(dateNotBefore), sdf.format(dateNotBefore)));
			}

			// Realiza a assinatura do conteudo
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			gen.addCertificates(this.generatedCertStore());
			String algorithmOID = algAndLength.getAlgID().getValue();

			logger.info(cadesMessagesBundle.getString("info.algorithm.id", algorithmOID));
			SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
					.setSignedAttributeGenerator(signedAttributeGenerator)
					.setUnsignedAttributeGenerator(unsignedAttributeGenerator)
					.build(AlgorithmNames.getAlgorithmNameByOID(algorithmOID), this.pkcs1.getPrivateKey(),
							this.certificate);
			gen.addSignerInfoGenerator(signerInfoGenerator);

			CMSTypedData cmsTypedData;
			// para assinatura do hash, content nulo
			if (content == null) {
				cmsTypedData = new CMSAbsentContent();
			} else {
				cmsTypedData = new CMSProcessableByteArray(content);
			}

			// TODO Estudar este método de contra-assinatura posteriormente
			if (previewSignature != null && previewSignature.length > 0) {
				gen.addSigners(cmsPreviewSignedData.getSignerInfos());
			}

			// Efetua a assinatura digital do conteúdo
			CMSSignedData cmsSignedData = gen.generate(cmsTypedData, this.attached);
			setAttached(false);


			// Consulta e adiciona os atributos não assinados//			
			logger.info(cadesMessagesBundle.getString("info.unsigned.attribute"));
			List<SignerInformation> vNewSigners = new ArrayList<SignerInformation>();
			SignerInformation oSi = cmsSignedData.getSignerInfos().getSigners().iterator().next();

			if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr()
					.getObjectIdentifiers() != null) {
				for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo()
						.getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules()
						.getMandatedUnsignedAttr().getObjectIdentifiers()) {

					SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
							.factory(objectIdentifier.getValue());
					signedOrUnsignedAttribute.initialize(this.pkcs1.getPrivateKey(), certificateChain, oSi.getSignature(),
							signaturePolicy, this.hash);
					unsignedAttributes.add(signedOrUnsignedAttribute.getValue());
				}
			}

			unsignedAttributesTable = new AttributeTable(unsignedAttributes);
			vNewSigners.add(SignerInformation.replaceUnsignedAttributes(oSi, unsignedAttributesTable));
			SignerInformationStore oNewSignerInformationStore = new SignerInformationStore(vNewSigners);
			CMSSignedData oSignedData = cmsSignedData;
			cmsSignedData = CMSSignedData.replaceSigners(oSignedData, oNewSignerInformationStore);

			
			byte[] result = cmsSignedData.getEncoded();

			return result;			

		} catch (CMSException | IOException | OperatorCreationException | CertificateEncodingException ex) {
			throw new SignerException(ex);
		}
	}
	

	@Override
	public void setSignaturePolicy(PolicyFactory.Policies signaturePolicy) {
		PolicyFactory policyFactory = PolicyFactory.getInstance();
		org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy sp = policyFactory.loadPolicy(signaturePolicy);
		this.signaturePolicy = sp;
	}

	/**
	 * 
	 * List of algorithms with their respective OID.
	 * 
	 * http://oid-info.com/basic-search.htm
	 *
	 */

	private enum AlgorithmNames {

		md2("1.2.840.113549.2.1", "MD2"),
		md2WithRSAEncryption("1.2.840.113549.1.1.2", "MD2withRSA"), 
		md5("1.2.840.113549.2.5","MD5"),
		md5WithRSAEncryption("1.2.840.113549.1.1.4", "MD5withRSA"),
		sha1("1.3.14.3.2.26", "SHA1"),
		sha1WithDSAEncryption("1.2.840.10040.4.3", "SHA1withDSA"),
		sha1WithECDSAEncryption("1.2.840.10045.4.1", "SHA1withECDSA"),
		sha1WithRSAEncryption("1.2.840.113549.1.1.5", "SHA1withRSA"),
		sha224("2.16.840.1.101.3.4.2.4", "SHA224"),
		sha224WithRSAEncryption("1.2.840.113549.1.1.14", "SHA224withRSA"),
		sha256("2.16.840.1.101.3.4.2.1", "SHA256"),
		sha256WithRSAEncryption("1.2.840.113549.1.1.11", "SHA256withRSA"),
		sha384("2.16.840.1.101.3.4.2.2", "SHA384"),
		sha384WithRSAEncryption("1.2.840.113549.1.1.12", "SHA384withRSA"),
		sha512("2.16.840.1.101.3.4.2.3", "SHA512"),
		sha512WithRSAEncryption("1.2.840.113549.1.1.13", "SHA512withRSA"),
		sha3_224("2.16.840.1.101.3.4.2.7", "SHA3-224"),
		sha3_256("2.16.840.1.101.3.4.2.8", "SHA3-256"),
		sha3_384("2.16.840.1.101.3.4.2.9", "SHA3-384"),
		sha3_512("2.16.840.1.101.3.4.2.10", "SHA3-512"),
		shake128("1.0.10118.3.0.62", "SHAKE128"),
		shake256("1.0.10118.3.0.63", "SHAKE256");

		private final String identifier;
		private final String algorithmName;

		private AlgorithmNames(String identifier, String name) {
			this.identifier = identifier;
			this.algorithmName = name;
		}

		private String getAlgorithmName() {
			return algorithmName;
		}

		private String getIdentifier() {
			return identifier;
		}

		public static String getAlgorithmNameByOID(String oid) {

			switch (oid) {

			case "1.2.840.113549.2.1": {
				return md2.getAlgorithmName();
			}
			case "1.2.840.113549.2.5": {
				return md5.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.4": {
				return md5WithRSAEncryption.getAlgorithmName();
			}
			case "1.3.14.3.2.26": {
				return sha1.getAlgorithmName();
			}
			case "1.2.840.10040.4.3": {
				return sha1WithDSAEncryption.getAlgorithmName();
			}
			case "1.2.840.10045.4.1": {
				return sha1WithECDSAEncryption.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.5": {
				return sha1WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.4": {
				return sha224.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.14": {
				return sha224WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.1": {
				return sha256.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.11": {
				return sha256WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.2": {
				return sha384.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.12": {
				return sha384WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.3": {
				return sha512.getAlgorithmName();
			}
			case "1.2.840.113549.1.1.13": {
				return sha512WithRSAEncryption.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.7": {
				return sha3_224.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.8": {
				return sha3_256.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.9": {
				return sha3_384.getAlgorithmName();
			}
			case "2.16.840.1.101.3.4.2.10": {
				return sha3_512.getAlgorithmName();
			}
			case "1.0.10118.3.0.62": {
				return shake128.getAlgorithmName();
			}
			case "1.0.10118.3.0.63": {
				return shake256.getAlgorithmName();
			}
			default: {
				return sha256WithRSAEncryption.getAlgorithmName();
			}
			}
		}

		public static String getOIDByAlgorithmName(String algorithmName) {

			switch (algorithmName) {

			case "MD2": {
				return md2.getIdentifier();
			}
			case "MD2withRSA": {
				return md2WithRSAEncryption.getIdentifier();
			}
			case "MD5": {
				return md5.getIdentifier();
			}
			case "MD5withRSA": {
				return md5WithRSAEncryption.getIdentifier();
			}
			case "SHA1": {
				return sha1.getIdentifier();
			}
			case "SHA1withDSA": {
				return sha1WithDSAEncryption.getIdentifier();
			}
			case "SHA1withECDSA": {
				return sha1WithECDSAEncryption.getIdentifier();
			}
			case "SHA1withRSA": {
				return sha1WithRSAEncryption.getIdentifier();
			}
			case "SAH224": {
				return sha224.getIdentifier();
			}
			case "SHA224withRSA": {
				return sha224WithRSAEncryption.getIdentifier();
			}
			case "SHA256": {
				return sha256.getIdentifier();
			}
			case "SHA256withRSA": {
				return sha256WithRSAEncryption.getIdentifier();
			}
			case "SHA384": {
				return sha384.getIdentifier();
			}
			case "SHA384withRSA": {
				return sha384WithRSAEncryption.getIdentifier();
			}
			case "SHA512": {
				return sha512.getIdentifier();
			}
			case "SHA512withRSA": {
				return sha512WithRSAEncryption.getIdentifier();
			}
			case "SHA3-224": {
				return sha3_224.getIdentifier();
			}
			case "SHA3-256": {
				return sha3_256.getIdentifier();
			}
			case "SHA3-384": {
				return sha3_384.getIdentifier();
			}
			case "SHA3-512": {
				return sha3_512.getIdentifier();
			}
			case "SHAKE128": {
				return shake128.getIdentifier();
			}
			case "SHAKE256": {
				return shake256.getIdentifier();
			}
			default: {
				return sha256WithRSAEncryption.getIdentifier();

			}
			}
		}
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
	public boolean checkAttached(byte[] signedData) {
		return this.check(null, signedData);
	}

	@Override
	public boolean checkDetattached(byte[] content, byte[] signedData) {
		return this.check(content, signedData);
	}

	@SuppressWarnings("unchecked")
	@Override
	public List<SignatureInfo> checkSignatureByHash(String digestAlgorithmOID, byte[] calculatedHashContent, byte[] signedData) throws SignerException{
		this.checkHash = true;
		this.hashes.put(digestAlgorithmOID, calculatedHashContent);
		this.hash = calculatedHashContent;
		if (this.check(null, signedData)){
			return this.getSignatureInfo();
		}else{
			return null;
		}		
	}

	public List<SignatureInfo> getSignatureInfo() {
		return signatureInfo;
	}

	public void setSignatureInfo(List<SignatureInfo> signatureInfo) {
		this.signatureInfo = signatureInfo;
	}

}