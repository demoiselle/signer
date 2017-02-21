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
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSAttributeTableGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgAndLength;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgorithmIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.CertificateTrustPoint;
import org.demoiselle.signer.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS1Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs1.PKCS1Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.SignedOrUnsignedAttribute;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.factory.AttributeFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CAdESSigner implements PKCS7Signer {

	private static final Logger logger = LoggerFactory
			.getLogger(CAdESSigner.class);

	private final PKCS1Signer pkcs1 = PKCS1Factory.getInstance()
			.factoryDefault();
	private X509Certificate certificate;
	private Certificate certificateChain[];
	private boolean attached = false;
	private SignaturePolicy signaturePolicy = null;
	private boolean defaultCertificateValidators = true;

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
	 * A validação se basea apenas em assinaturas com um assinante apenas.
	 * Valida apenas com o conteúdo do tipo DATA: OID ContentType
	 * 1.2.840.113549.1.9.3 = OID Data 1.2.840.113549.1.7.1
	 *
	 * @params content Necessário informar apenas se o pacote PKCS7 NÃO for do
	 *         tipo ATTACHED. Caso seja do tipo attached, este parâmetro será
	 *         substituido pelo conteúdo do pacote PKCS7.
	 * @params signed Valor em bytes do pacote PKCS7, como por exemplo o
	 *         conteúdo de um arquivo ".p7s". Não é a assinatura pura como no
	 *         caso do PKCS1. TODO: Implementar validação de co-assinaturas
	 */
	@Override
	public boolean check(byte[] content, byte[] signedData) {
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData cmsSignedData = null;
		try {
			if (content == null) {
				cmsSignedData = new CMSSignedData(signedData);
			} else {
				cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(
						content), signedData);
			}
		} catch (CMSException ex) {
			throw new SignerException(
					"Bytes inválidos localizados no pacote PKCS7.", ex);
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
				Collection<?> certCollection = certStore.getMatches(signer.getSID());

				Iterator<?> certIt = certCollection.iterator();
				X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt
						.next();

				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
						.setProvider("BC").build(certificateHolder))) {
					verified++;
					logger.info(
							"Validada a assinatura digital de sequencia [{}]",
							verified);
				}

				// Realiza a verificação dos atributos assinados
				logger.info("Efetuando a verificação dos atributos assinados");
				AttributeTable signedAttributes = signer.getSignedAttributes();
				if ((signedAttributes == null)
						|| (signedAttributes != null && signedAttributes.size() == 0)) {
					throw new SignerException(
							"O pacote PKCS7 não contém atributos assinados.");
				}

				AttributeTable unsignedAttributes = signer
						.getUnsignedAttributes();
				if ((unsignedAttributes == null)
						|| (unsignedAttributes != null && unsignedAttributes
								.size() == 0)) {
					logger.info("O pacote PKCS7 não contem atributos nao assinados.");
				}

				// Mostra a hora da assinatura
				logger.info(
						"UTCTime yyMMddHHmmssz : {}",
						(((ASN1UTCTime) signedAttributes
								.get(new ASN1ObjectIdentifier(
										"1.2.840.113549.1.9.5"))
								.getAttrValues().getObjectAt(0)).getTime()));

				logger.info("Iniciando a validacao dos atributos");
				// Valida o atributo ContentType
				Attribute attributeContentType = signedAttributes
						.get(CMSAttributes.contentType);
				if (attributeContentType == null) {
					throw new SignerException(
							"O pacote PKCS7 não contém o atributo \"ContentType\"");
				}

				if (!attributeContentType.getAttrValues().getObjectAt(0)
						.equals(ContentInfo.data)) {
					throw new SignerException(
							"\"ContentType\" não é do tipo \"DATA\"");
				}

				// Validando o atributo MessageDigest
				Attribute attributeMessageDigest = signedAttributes
						.get(CMSAttributes.messageDigest);
				if (attributeMessageDigest == null) {
					throw new SignerException(
							"O pacote PKCS7 não contém o atributo \"MessageDigest\"");
				}
			} catch (OperatorCreationException
					| java.security.cert.CertificateException ex) {
				throw new SignerException(ex);
			} catch (CMSException ex) {
				throw new SignerException("A assinatura fornecida é inválida.",
						ex);
			}
		}

		logger.info("Verificada(s) {} assinatura(s).", verified);
		// TODO Efetuar o parsing da estrutura CMS
		return true;
	}

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
		return this.signaturePolicy.getSignPolicyHashAlg().getAlgorithm()
				.getValue();
	}

	/**
	 * Retorna o conteúdo original do arquivo assinado
	 *
	 * @param signed
	 *            O conteúdo assinado
	 * @return O conteúdo original
	 */
	public byte[] getAttached(byte[] signed) {
		return this.getAttached(signed, true);
	}

	/**
	 * Extrai o conteudo assinado da estrutura de assinatura digital, caso
	 * exista
	 *
	 * @param signed
	 *            O conteudo assinado
	 * @param validateOnExtract
	 *            Extrai validando a assinatura, em caso verdadeiro.
	 * @return O conteudo original
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
			throw new SignerException("Invalid bytes for a package PKCS7",
					exception);
		}

		try {
			CMSProcessable contentProcessable = signedData.getSignedContent();
			if (contentProcessable != null) {
				result = (byte[]) contentProcessable.getContent();
			}
		} catch (Exception exception) {
			throw new SignerException("Error on get content from PKCS7",
					exception);
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

	public void setDefaultCertificateValidators(
			boolean defaultCertificateValidators) {
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
	 * Método de assinatura de dados e geração do pacote PKCS7 Assina apenas com
	 * o conteúdo do tipo DATA: OID ContentType 1.2.840.113549.1.9.3 = OID Data
	 * 1.2.840.113549.1.7.1 Utiliza o algoritmo da propriedade algorithm. Caso
	 * essa propriedade não seja informada, o algoritmo do enum
	 * {@link SignerAlgorithmEnum.DEFAULT} será usado. Para este método é
	 * necessário informar o conteúdo, a chave privada e um certificado digital
	 * padrão ICP-Brasil.
	 *
	 * @param content
	 *            Conteúdo a ser assinado. TODO: Implementar co-assinaturas,
	 *            informar a política de assinatura
	 */
	
	private byte[] doSign(byte[] content) {
		try {
			Security.addProvider(new BouncyCastleProvider());

			// Completa os certificados ausentes da cadeia, se houver
			if (this.certificate == null && this.certificateChain != null
					&& this.certificateChain.length > 0) {
				this.certificate = (X509Certificate) this.certificateChain[0];
			}

			if (this.certificateChain == null
					|| this.certificateChain.length <= 1) {
				this.certificateChain = CAManager.getInstance()
						.getCertificateChainArray(this.certificate);
			}

			// Recupera a lista de algoritmos da politica e o tamanho minimo da chave
			List<AlgAndLength>  listOfAlgAndLength = new ArrayList<AlgAndLength>();

			for (AlgAndLength algLength : signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
					.getAlgorithmConstraintSet()
					.getSignerAlgorithmConstraints().getAlgAndLengths()){
				listOfAlgAndLength.add(algLength);
		}
			AlgAndLength algAndLength = null;
			
			// caso o algoritmo tenha sido informado como parâmetro  irá verificar se o mesmo é permitido pela politica
			if (this.pkcs1.getAlgorithm() != null){
				String varSetedAlgorithmOID = AlgorithmNames.getOIDByAlgorithmName(this.pkcs1.getAlgorithm());
				for (AlgAndLength algLength : listOfAlgAndLength){
					if (algLength.getAlgID().getValue().equalsIgnoreCase(varSetedAlgorithmOID)){
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
			}else{
				algAndLength = listOfAlgAndLength.get(0);
			}
			if (algAndLength == null){
				throw new SignerException("Algoritmo informado no parâmetro não corresponde a nenhum contido na Politica!");
			}
			logger.info("AlgID........... {}", algAndLength.getAlgID()
					.getValue());
			logger.info("Alg Name........ {}", AlgorithmNames
					.getAlgorithmNameByOID(algAndLength.getAlgID().getValue()));
			logger.info("Defautl Alg OID of Policy {}",
					AlgorithmNames.getOIDByAlgorithmName(getAlgorithm()));
			logger.info("MinKeyLength.... {}", algAndLength.getMinKeyLength());

			
			// Recupera o tamanho minimo da chave para validacao
			logger.info("Validando o tamanho da chave");
			if (((RSAKey) certificate.getPublicKey()).getModulus().bitLength() < algAndLength
					.getMinKeyLength()) {
				throw new SignerException(
						"O tamanho mínimo da chave  deve ser de ".concat(
								algAndLength.getMinKeyLength().toString())
								.concat(" bits"));
			}
			
			
			AttributeFactory attributeFactory = AttributeFactory.getInstance();

			// Consulta e adiciona os atributos assinados
			ASN1EncodableVector signedAttributes = new ASN1EncodableVector();

			logger.info("Identificando os atributos assinados");
			if (signaturePolicy.getSignPolicyInfo()
					.getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules()
					.getMandatedSignedAttr().getObjectIdentifiers() != null) {
				for (ObjectIdentifier objectIdentifier : signaturePolicy
						.getSignPolicyInfo().getSignatureValidationPolicy()
						.getCommonRules().getSignerAndVeriferRules()
						.getSignerRules().getMandatedSignedAttr()
						.getObjectIdentifiers()) {

					SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
							.factory(objectIdentifier.getValue());
					signedOrUnsignedAttribute.initialize(
							this.pkcs1.getPrivateKey(), certificateChain,
							content, signaturePolicy);
					signedAttributes.add(signedOrUnsignedAttribute.getValue());
				}
			}

			// Consulta e adiciona os atributos não assinados
			ASN1EncodableVector unsignedAttributes = new ASN1EncodableVector();
			logger.info("Identificando os atributos não assinados");
			if (signaturePolicy.getSignPolicyInfo()
					.getSignatureValidationPolicy().getCommonRules()
					.getSignerAndVeriferRules().getSignerRules()
					.getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
				for (ObjectIdentifier objectIdentifier : signaturePolicy
						.getSignPolicyInfo().getSignatureValidationPolicy()
						.getCommonRules().getSignerAndVeriferRules()
						.getSignerRules().getMandatedUnsignedAttr()
						.getObjectIdentifiers()) {

					SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
							.factory(objectIdentifier.getValue());
					signedOrUnsignedAttribute.initialize(
							this.pkcs1.getPrivateKey(), certificateChain,
							content, signaturePolicy);
					unsignedAttributes
							.add(signedOrUnsignedAttribute.getValue());
				}
			}

			// Monta a tabela de atributos assinados e não assinados
			AttributeTable signedAttributesTable = new AttributeTable(
					signedAttributes);
			AttributeTable unsignedAttributesTable = new AttributeTable(
					unsignedAttributes);

			// Create the table table generator that will added to the Signer
			// builder
			CMSAttributeTableGenerator signedAttributeGenerator = new DefaultSignedAttributeTableGenerator(
					signedAttributesTable);
			CMSAttributeTableGenerator unsignedAttributeGenerator = new SimpleAttributeTableGenerator(
					unsignedAttributesTable);


			// Recupera o(s) certificado(s) de confianca para validacao
			Collection<X509Certificate> trustedCAs = new HashSet<X509Certificate>();

			Collection<CertificateTrustPoint> ctp = signaturePolicy
					.getSignPolicyInfo().getSignatureValidationPolicy()
					.getCommonRules().getSigningCertTrustCondition()
					.getSignerTrustTrees().getCertificateTrustPoints();
			for (CertificateTrustPoint certificateTrustPoint : ctp) {
				logger.info("Trust Point... {}", certificateTrustPoint
						.getTrustpoint().getSubjectDN().toString());
				trustedCAs.add(certificateTrustPoint.getTrustpoint());
			}
			// Efetua a validacao das cadeias do certificado baseado na politica
			CAManager.getInstance().validateRootCAs(trustedCAs, certificate);

			// Recupera a data de validade da politica para validacao
			logger.info("Verificando o período de validade da politica");
			Date dateNotBefore = signaturePolicy.getSignPolicyInfo()
					.getSignatureValidationPolicy().getSigningPeriod()
					.getNotBefore().getDate();
			Date dateNotAfter = signaturePolicy.getSignPolicyInfo()
					.getSignatureValidationPolicy().getSigningPeriod()
					.getNotAfter().getDate();

			Date actualDate = new GregorianCalendar().getTime();

			if (actualDate.before(dateNotBefore)
					|| actualDate.after(dateNotAfter)) {
				SimpleDateFormat sdf = new SimpleDateFormat(
						"dd/MM/yyyy - hh:mm:ss");
				throw new SignerException(
						"Esta política é válida somente entre "
								.concat(sdf.format(dateNotBefore))
								.concat(" e ")
								.concat(sdf.format(dateNotBefore)));
			}

			// Realiza a assinatura do conteudo
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			gen.addCertificates(this.generatedCertStore());
			String algorithmOID = algAndLength.getAlgID().getValue();

			logger.info("algorithOID...: " + algorithmOID);
			SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
					.setSignedAttributeGenerator(signedAttributeGenerator)
					.setUnsignedAttributeGenerator(unsignedAttributeGenerator)
					.build(AlgorithmNames.getAlgorithmNameByOID(algorithmOID),
							this.pkcs1.getPrivateKey(), this.certificate);
			gen.addSignerInfoGenerator(signerInfoGenerator);

			CMSTypedData cmsTypedData;
			if (content == null) {
				// TODO Verificar a necessidade da classe CMSAbsentContent local
				cmsTypedData = new CMSAbsentContent();
			} else {
				cmsTypedData = new CMSProcessableByteArray(content);
			}

			// TODO Estudar este método de contra-assinatura posteriormente
			// gen.generateCounterSigners(null);
			// Efetua a assinatura digital do conteúdo
			CMSSignedData cmsSignedData = gen.generate(cmsTypedData,
					this.attached);

			// Código a seguir para substituir a o atributo IdAaSignatureTimeStampToken
			
			SignerInformationStore oOrigSignerInfoStore = cmsSignedData
					.getSignerInfos();

			List<SignerInformation> vNewSigners = new ArrayList<SignerInformation>();

			Collection<?> ovSigners = oOrigSignerInfoStore.getSigners();
	
             for (Iterator<?> iter = ovSigners.iterator(); iter.hasNext();)
             {
                 SignerInformation oSi = (SignerInformation) iter.next();
      			ASN1EncodableVector newUnsignedAttributes = new ASN1EncodableVector();
      			logger.info("Identificando os atributos não assinados");
      			if (signaturePolicy.getSignPolicyInfo()
      					.getSignatureValidationPolicy().getCommonRules()
      					.getSignerAndVeriferRules().getSignerRules()
      					.getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
      				for (ObjectIdentifier objectIdentifier : signaturePolicy
      						.getSignPolicyInfo().getSignatureValidationPolicy()
      						.getCommonRules().getSignerAndVeriferRules()
      						.getSignerRules().getMandatedUnsignedAttr()
      						.getObjectIdentifiers()) {

      					SignedOrUnsignedAttribute signedOrUnsignedAttribute = attributeFactory
      							.factory(objectIdentifier.getValue());
      					signedOrUnsignedAttribute.initialize(
      							this.pkcs1.getPrivateKey(), certificateChain,
      							oSi.getSignature(), signaturePolicy);
      					newUnsignedAttributes
      							.add(signedOrUnsignedAttribute.getValue());
      				}
      			}
      			AttributeTable newUnsignedAttributesTable = new AttributeTable(
      					newUnsignedAttributes);
                  vNewSigners.add(SignerInformation.replaceUnsignedAttributes(oSi,newUnsignedAttributesTable));
             } 
			SignerInformationStore oNewSignerInformationStore = new SignerInformationStore(
					vNewSigners);

			CMSSignedData oSignedData = cmsSignedData;
			cmsSignedData = CMSSignedData.replaceSigners(oSignedData,
					oNewSignerInformationStore); 

			byte[] result = cmsSignedData.getEncoded();

			return result;

		} catch (CMSException | IOException | OperatorCreationException
				| CertificateEncodingException ex) {
			throw new SignerException(ex);
		}
	}

	@Override
	public void setSignaturePolicy(PolicyFactory.Policies signaturePolicy) {
		PolicyFactory policyFactory = PolicyFactory.getInstance();
		org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy sp = policyFactory
				.loadPolicy(signaturePolicy);
		this.signaturePolicy = sp;
	}

	/**
	 * 
	 * Lista de algoritmos com seus respectivos OID see
	 * http://oid-info.com/basic-search.htm
	 *
	 */

	private enum AlgorithmNames {

		md2("1.2.840.113549.2.1", "MD2"), 
		md2WithRSAEncryption("1.2.840.113549.1.1.2", "MD2withRSA"), 
		md5("1.2.840.113549.2.5", "MD5"), 
		md5WithRSAEncryption("1.2.840.113549.1.1.4", "MD5withRSA"), 
		sha1("1.3.14.3.2.26","SHA1"), 
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

}
