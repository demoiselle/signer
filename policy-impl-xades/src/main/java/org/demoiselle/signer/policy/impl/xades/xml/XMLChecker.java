package org.demoiselle.signer.policy.impl.xades.xml;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.TimeZone;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignerDigestMismatchException;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateRevocationException;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.validator.CRLValidator;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.Checker;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.demoiselle.signer.timestamp.Timestamp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XMLChecker implements Checker{
	
	private static final Logger logger = LoggerFactory.getLogger(CAdESChecker.class);

	@Override
	public List<SignatureInformations> checkAttachedSignature(byte[] signedData) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<SignatureInformations> checkDetattachedSignature(byte[] content, byte[] signedData) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<SignatureInformations> checkDetachedSignature(byte[] content, byte[] signedData) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public List<SignatureInformations> checkSignatureByHash(String digestAlgorithmOID, byte[] calculatedHashContent,
			byte[] signedData) {
		// TODO Auto-generated method stub
		return null;
	}
	
	private boolean check(byte[] content, byte[] signedData) throws SignerException{
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData cmsSignedData = null;
		/*TODO Get data form ENVELOPED or DETACHED
		try {
			//Get data form ENVELOPED or DETACHED
		} catch (CMSException ex) {
			throw new SignerException(cadesMessagesBundle.getString("error.invalid.bytes.pkcs7"), ex);
		}*/

		// Quantity of validate signatures
		/*int verified = 0;

		Store<?> certStore = cmsSignedData.getCertificates();
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		Iterator<?> it = signers.getSigners().iterator();

		// Realização da verificação básica de todas as assinaturas
		while (it.hasNext()) {
			SignatureInformations signatureInfo = new SignatureInformations();
			try {
				SignerInformation signerInfo = (SignerInformation) it.next();
				SignerInformationStore signerInfoStore = signerInfo.getCounterSignatures();
				
				logger.info("Foi(ram) encontrada(s) " + signerInfoStore.size() + " contra-assinatura(s).");

				@SuppressWarnings("unchecked")
				Collection<?> certCollection = certStore.getMatches(signerInfo.getSID());

				Iterator<?> certIt = certCollection.iterator();
				X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
				
				X509Certificate varCert = new JcaX509CertificateConverter().getCertificate(certificateHolder);
					
				CRLValidator cV = new CRLValidator();				
				try {
					cV.validate(varCert);	
				}catch (CertificateValidatorCRLException cvce) {
					signatureInfo.getValidatorErrors().add(cvce.getMessage());
					logger.info(cvce.getMessage());
				}catch (CertificateRevocationException cre) {
					signatureInfo.getValidatorErrors().add(cre.getMessage());
					logger.info("certificado revogado");
				}
				
				PeriodValidator pV = new PeriodValidator();				
				try{
					signatureInfo.setNotAfter(pV.valDate(varCert));			
				}catch (CertificateValidatorException cve) {
					signatureInfo.getValidatorErrors().add(cve.getMessage());
				}
				
				if (signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificateHolder))) {
					verified++;
					logger.info(cadesMessagesBundle.getString("info.signature.valid.seq", verified));
				}				
			
				
				
				// recupera atributos assinados
				logger.info(cadesMessagesBundle.getString("info.signed.attribute"));
				String varOIDPolicy = PKCSObjectIdentifiers.id_aa_ets_sigPolicyId.getId();
				AttributeTable signedAttributes = signerInfo.getSignedAttributes();
				if ((signedAttributes == null) || (signedAttributes != null && signedAttributes.size() == 0)) {
					signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.signed.attribute.table.not.found"));
					logger.info(cadesMessagesBundle.getString("error.signed.attribute.table.not.found"));
					//throw new SignerException(cadesMessagesBundle.getString("error.signed.attribute.table.not.found"));
				}else{
					//Validando atributos assinados de acordo com a politica
					Attribute idSigningPolicy = null;					
					idSigningPolicy = signedAttributes.get(new ASN1ObjectIdentifier(varOIDPolicy));
					if (idSigningPolicy == null) {							
							signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.pcks7.attribute.not.found",varOIDPolicy));
					}else{
						for (Enumeration<?> p = idSigningPolicy.getAttrValues().getObjects(); p.hasMoreElements();){
							String policyOnSignature = p.nextElement().toString();
							for (PolicyFactory.Policies pv : PolicyFactory.Policies.values()){
								if (policyOnSignature.contains(pv.getUrl())){
									setSignaturePolicy(pv);
									break;
								}							
							}
						}						
					}
				}
				Date dataHora = null;
				if (signedAttributes != null) {
					// Valida o atributo ContentType
					Attribute attributeContentType = signedAttributes.get(CMSAttributes.contentType);
					if (attributeContentType == null) {
						signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.pcks7.attribute.not.found", "ContentType"));
						//throw new SignerException(cadesMessagesBundle.getString("error.pcks7.attribute.not.found", "ContentType"));
						logger.info(cadesMessagesBundle.getString("error.pcks7.attribute.not.found", "ContentType"));
					}

					if (!attributeContentType.getAttrValues().getObjectAt(0).equals(ContentInfo.data)) {
						signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.content.not.data"));
						//throw new SignerException(cadesMessagesBundle.getString("error.content.not.data"));
						logger.info(cadesMessagesBundle.getString("error.content.not.data"));
					}

					// Validando o atributo MessageDigest
					Attribute attributeMessageDigest = signedAttributes.get(CMSAttributes.messageDigest);
					if (attributeMessageDigest == null) {
						throw new SignerException(
								cadesMessagesBundle.getString("error.pcks7.attribute.not.found", "MessageDigest"));
					}
					// Mostra data e  hora da assinatura, não é carimbo de tempo
					Attribute timeAttribute = signedAttributes.get(CMSAttributes.signingTime);
					
					if (timeAttribute != null) {
						TimeZone.setDefault(null);
						dataHora = (((ASN1UTCTime) timeAttribute.getAttrValues().getObjectAt(0)).getDate());
						logger.info(cadesMessagesBundle.getString("info.date.utc",dataHora));																
					} else {
						logger.info(cadesMessagesBundle.getString("info.date.utc","N/D"));
					}

				}
								
				if (signaturePolicy == null){
					signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.policy.on.component.not.found", varOIDPolicy));
					logger.info(cadesMessagesBundle.getString("error.policy.on.component.not.found"));
				}else{					
					if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
							.getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr()
							.getObjectIdentifiers() != null) {
						for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo()
								.getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules()
								.getMandatedSignedAttr().getObjectIdentifiers()) {
								String oi = objectIdentifier.getValue();
								Attribute signedAtt = signedAttributes.get(new ASN1ObjectIdentifier(oi));
								logger.info(oi);
								if (signedAtt == null){
								signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.signed.attribute.not.found",oi,signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier().getValue() ));
								}										
						}
					}
				}
				
			
				
				// recupera os atributos NÃO assinados
				logger.info(cadesMessagesBundle.getString("info.unsigned.attribute"));
				AttributeTable unsignedAttributes = signerInfo.getUnsignedAttributes();
				if ((unsignedAttributes == null) || (unsignedAttributes != null && unsignedAttributes.size() == 0)) {
					// Apenas info pois a RB não tem atributos não assinados
					logger.info(cadesMessagesBundle.getString("error.unsigned.attribute.table.not.found"));
				}
				if (signaturePolicy != null){
					// Validando atributos NÃO assinados de acordo com a politica
					if (signaturePolicy.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules()
							.getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr()
							.getObjectIdentifiers() != null) {
							for (ObjectIdentifier objectIdentifier : signaturePolicy.getSignPolicyInfo()
								.getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules()
								.getMandatedUnsignedAttr().getObjectIdentifiers()) {
								String oi = objectIdentifier.getValue();
								Attribute unSignedAtt = unsignedAttributes.get(new ASN1ObjectIdentifier(oi));
								logger.info(oi);
								if (unSignedAtt == null){
									signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.unsigned.attribute.not.found",oi,signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier().getValue() ));
								}
								if (oi.equalsIgnoreCase(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId())){
									//Verificando timeStamp
									try{
											byte[] varSignature = signerInfo.getSignature();
											Timestamp varTimeStampSigner = validateTimestamp(unSignedAtt, varSignature); 
											signatureInfo.setTimeStampSigner(varTimeStampSigner);
									}catch (Exception ex) {
										signatureInfo.getValidatorErrors().add(ex.getMessage());
										// nas assinaturas feitas na applet o unsignedAttributes.get gera exceção.						
									}
								}
								if (oi.equalsIgnoreCase("1.2.840.113549.1.9.16.2.25")){
									logger.info("++++++++++  EscTimeStamp ++++++++++++");
								}
							}
						}						
				}
				
				LinkedList<X509Certificate> varChain = (LinkedList<X509Certificate>) CAManager.getInstance().getCertificateChain(varCert);
				if (varChain.size() < 3){
					signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.no.ca", varCert.getIssuerDN()));
					logger.info(cadesMessagesBundle.getString("error.no.ca", varCert.getIssuerDN()));
				}
				signatureInfo.setSignDate(dataHora);
				signatureInfo.setChain(varChain);
				signatureInfo.setSignaturePolicy(signaturePolicy);
				this.getSignaturesInfo().add(signatureInfo);
				
			} catch (OperatorCreationException | java.security.cert.CertificateException ex) {
				signatureInfo.getValidatorErrors().add(ex.getMessage());
				logger.info(ex.getMessage());
			} catch (CMSException ex) {				
				// When file is mismatch with sign
				if (ex instanceof CMSSignerDigestMismatchException){
					signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.signature.mismatch"));
					logger.info(cadesMessagesBundle.getString("error.signature.mismatch"));
					throw new SignerException(cadesMessagesBundle.getString("error.signature.mismatch"), ex);
				}					
				else{
					signatureInfo.getValidatorErrors().add(cadesMessagesBundle.getString("error.signature.invalid", ex.getMessage()));
					logger.info(cadesMessagesBundle.getString("error.signature.invalid", ex.getMessage()));
					throw new SignerException(cadesMessagesBundle.getString("error.signature.invalid", ex.getMessage()), ex);
				}
			} catch (ParseException e) {
				signatureInfo.getValidatorErrors().add(e.getMessage());
				logger.info(e.getMessage());
			} 
		}
		logger.info(cadesMessagesBundle.getString("info.signature.verified", verified));
		// TODO Efetuar o parsing da estrutura CMS*/
		return true;
	}

}
