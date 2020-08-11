package org.demoiselle.signer.policy.impl.xades.xml;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


//Validate type of signature like ENVELOPED

public class XMLChecker {
	
	private static final Logger logger = LoggerFactory.getLogger(CAdESChecker.class);
	private XMLSigner signer = new XMLSigner();
	
	public PolicyFactory.Policies getPolicyByOid(String oid) {
		
		switch (oid) {
		case "2.16.76.1.7.1.6.2.2":
			return PolicyFactory.Policies.AD_RB_XADES_2_2;
		case "2.16.76.1.7.1.6.2.3":
			return PolicyFactory.Policies.AD_RB_XADES_2_3;
		case "2.16.76.1.7.1.6.2.4":
			return PolicyFactory.Policies.AD_RB_XADES_2_4;

		default:
			return null;
		}
	}
	
	List<String> validationErrors  = new ArrayList<String>();
	List<String> validationWaring  = new ArrayList<String>();
	
	public Element getSignatureElement(String tagName, Element parent, boolean mandatory){
		NodeList value = parent.getElementsByTagNameNS(XMLSigner.XMLNS, tagName);
		if(value.getLength() == 0) {
			if(mandatory)
				validationErrors.add("Element: "+tagName+ " not found");
			else
				validationWaring.add("Element: "+tagName+ " not found");
		}
		return (Element) value.item(0);
	}
	
	public Element getXadesElement(String tagName, Element parent, boolean mandatory){
		NodeList value = parent.getElementsByTagNameNS(XMLSigner.XAdESv1_3_2, tagName);
		if(value.getLength() == 0) {
			if(mandatory)
				validationErrors.add("Element: "+tagName+ " not found");
			else
				validationWaring.add("Element: "+tagName+ " not found");
			return null;
		}
		return (Element) value.item(0);
	}
	
	public String getAttribute(Element node, String attr, boolean mandatory){
		String attribute = node.getAttribute(attr);
		if(attr.isEmpty()) {
			if(mandatory)
				validationErrors.add("Attribute: "+attr+ " not found");
			else
				validationWaring.add("Attribute: "+attr+ " not found");
		}
		return attribute;
	}
	
	private boolean verifyDigest(Element signatureTag, String digestMethod, String digestValue, String canonicalString) {
		Element objectTag = (Element)signatureTag.getElementsByTagNameNS(XMLSigner.XMLNS,"Object").item(0);
		
		byte[] canonicalized = null;
		Init.init();
		Canonicalizer c14n;
		try {
			c14n = Canonicalizer.getInstance(canonicalString);
			canonicalized = c14n.canonicalizeSubtree(objectTag.getElementsByTagName("xades:SignedProperties").item(0)); 
		} catch (InvalidCanonicalizerException | CanonicalizationException e1) {
			validationErrors.add("Dados do resumo inválidos: "+digestMethod);
			logger.debug("Dados do resumo inválidos: "+digestMethod);
			return false;
		}
		MessageDigest md = null;
		
		try {
			String algorithm = AlgorithmsValues.getSignatureDigest(digestMethod);
			if(algorithm != null) {
				md = MessageDigest.getInstance(algorithm);
				byte[] signatureDigestValue = md.digest(canonicalized);
				if(!Base64.toBase64String(signatureDigestValue).equals(digestValue)) {
					validationErrors.add("Valor do resumo inválido");
					return false;
				}
			}else {
				validationErrors.add("Invalid signature hash algorithm: "+digestMethod);
				logger.debug("Invalid signature hash algorithm: "+digestMethod);
				return false;
			}
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add("Algoritmo inválido: "+digestMethod);
			
			return false;
		}
		return true;
	}
	
	private boolean verifyXPath(Document doc, String digestMethod, String digestValue, NodeList transformsTags) {
		
		String xPathTransformAlgorithm = "";
		
		for(int i = 0; i < transformsTags.getLength(); i++) {	
			NodeList transformTag = ((Element)transformsTags.item(i)).getElementsByTagNameNS(XMLSigner.XMLNS, "Transform");
			for(int j = 0; j < transformTag.getLength(); j++) {
				if(((Element)transformTag.item(j)).getAttribute("Algorithm").equals("http://www.w3.org/2001/10/xml-exc-c14n#")) {
					xPathTransformAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
					break;
				}
			}
		}
		
		try {
			Element docData = signer.getDocumentData(doc);
			byte[] docHash = signer.getShaCanonizedValue(AlgorithmsValues.getSignatureDigest(digestMethod), docData, xPathTransformAlgorithm);
			if(!Base64.toBase64String(docHash).equals(digestValue)) {
				
				return false;
			}
		} catch (Exception e) {
			validationErrors.add("Erro ao validar o resumo do documento");
			logger.debug("Erro ao validar o resumo do documento");
			return false;
		}
		
		return true;
	}
	
	private X509Certificate getCertificate(String x509Certificate) throws CertificateException {
		byte encodedCert[] = Base64.decode(x509Certificate);
		ByteArrayInputStream inputStream  =  new ByteArrayInputStream(encodedCert);
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		return (X509Certificate)certFactory.generateCertificate(inputStream); 
	}
	
	private boolean verifyHash(Element signatureTag, Element signatureInfoTag, String signatureValue, X509Certificate cert) {
		
		try {
			Element canonicalizationMethodTag = (Element)signatureTag.getElementsByTagNameNS(XMLSigner.XMLNS, "CanonicalizationMethod").item(0);
			Element signatureMethod = (Element)signatureTag.getElementsByTagNameNS(XMLSigner.XMLNS, "SignatureMethod").item(0);
			
			
			
			Init.init();
			Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethodTag.getAttribute("Algorithm"));
		
			byte[] dh = c14n.canonicalizeSubtree(signatureInfoTag);
			
			Signature verify = Signature.getInstance(AlgorithmsValues.getSignatureAlgorithm(signatureMethod.getAttribute("Algorithm")));
			verify.initVerify(cert);
			verify.update(dh);
			if(!verify.verify(Base64.decode(signatureValue))){
				validationErrors.add("Resumo criptográfico da assinatura inválido");
			}else {
				return true;
			}
				
					
		}catch (InvalidCanonicalizerException | CanonicalizationException | InvalidKeyException | DOMException e) {
			validationErrors.add("Erro ao validar o resumo criptográfico da assinatura");
		}catch(NoSuchAlgorithmException e) {
			validationErrors.add("Algorítmo de assinatura inválido ou não suportado");
		}catch(SignatureException e) {
			validationErrors.add("Conteúdo da assinatura inválido");
		}
		
		return false;
		
	}
	
	private Element getElement(String value, Element doc) {
		
		NodeList nl = doc.getElementsByTagName(value);
		if(nl.getLength() > 0)
			return (Element)nl.item(0);
		
		return null;
	}
	
	private void verifyPolicy(Element signature, String policyOID, String signatureMethod, String signatureValue) {
		boolean isValidAlgorithm = false;
		try {
			Document doc = PolicyFactory.getInstance().loadXMLPolicy(getPolicyByOid(policyOID));
			Element mandatedSignedQProperties = getElement("pa:MandatedSignedQProperties", doc.getDocumentElement());
			NodeList qPropertyID = mandatedSignedQProperties.getElementsByTagName("pa:QPropertyID");
			NodeList signingPeriod = doc.getElementsByTagName("pa:SigningPeriod");
			NodeList algorithmConstraintSet = doc.getElementsByTagName("pa:AlgorithmConstraintSet");
			
			for(int i = 0; i < qPropertyID.getLength(); i++) {
				String tagText = qPropertyID.item(i).getTextContent();
				if(signature.getElementsByTagNameNS(XMLSigner.XAdESv1_3_2, tagText).getLength() < 1) {
					validationWaring.add("Elemento "+tagText+" obrigatório para a política não encontrado");
				}				
			}
			if(signingPeriod.getLength() > 0) {
				Element notBefore = getElement("pa:NotBefore", (Element)signingPeriod.item(0));
				Element notAfter = getElement("pa:NotAfter", (Element)signingPeriod.item(0));
				
				//Use local system date
			}
			
			for(int i = 0; i < algorithmConstraintSet.getLength(); i++) {
				Element algId = getElement("pa:AlgId", (Element)algorithmConstraintSet.item(i));
				Element minKeyLength = getElement("pa:MinKeyLength", (Element)algorithmConstraintSet.item(i));
				if(algId != null) {
					if(algId.getTextContent().equals(signatureMethod)) {
						if(minKeyLength != null) {
							if((8 * Base64.decode(signatureValue).length) >= Integer.parseInt(minKeyLength.getTextContent())) {
								isValidAlgorithm = true;
							}else {
								validationWaring.add("Tamanho da chave criptográfica menor que a requisitada pela política");
							}
						}
						break;
					}
				}
			}
			if(!isValidAlgorithm) {
				validationWaring.add("Algoritmo inválido para a política "+policyOID);

			}
			
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		}catch (SAXException | IOException e) {
			e.printStackTrace();
		}
		
	}
	
	
	public void verify(String fileName) {
		
		File fXmlFile = new File(fileName);
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		DocumentBuilder dBuilder;
		try {
			dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);
			String canonicalizationMethod = "";
			String signatureMethod = "";
			
			NodeList signatureListTags = doc.getElementsByTagNameNS(XMLSigner.XMLNS, "Signature");
			if(signatureListTags.getLength() < 0) {
				validationErrors.add("O documento não contém assinatura");
				return;
			}else {
				for(int i = 0; i < signatureListTags.getLength(); i++) {
					 
					Element signatureTag = (Element)signatureListTags.item(i);
					Element signatureInfoTag = getSignatureElement("SignedInfo", signatureTag, true);
					Element canonicalizationMethodTag = getSignatureElement("CanonicalizationMethod", signatureTag, true);
					canonicalizationMethod = getAttribute(canonicalizationMethodTag, "Algorithm", true);
					Element signatureMethodTag = getSignatureElement("SignatureMethod", signatureTag, true);
					signatureMethod = getAttribute(signatureMethodTag, "Algorithm", true);
					NodeList referenceTag = doc.getElementsByTagNameNS(XMLSigner.XMLNS,"Reference");
					
					
					for(int j = 0; j < referenceTag.getLength(); j++) {
						Element actualReferenceTag = (Element)referenceTag.item(j);
						NodeList transformsTags = actualReferenceTag.getElementsByTagNameNS(XMLSigner.XMLNS, "Transforms");

						Element digestMethodTag = getSignatureElement("DigestMethod", (Element)referenceTag.item(j), true);
						String digestMethod = getAttribute(digestMethodTag, "Algorithm", true);
						Element digestValueTag = getSignatureElement("DigestValue", (Element)referenceTag.item(j), true);
						String digestValue = digestValueTag.getTextContent();
						
						if(actualReferenceTag.getElementsByTagNameNS(XMLSigner.XMLNS, "XPath").getLength() > 0) {
							verifyXPath(doc, digestMethod, digestValue, transformsTags);
						}else if(((Element)referenceTag.item(j)).hasAttribute("Type")) {
							if(((Element)referenceTag.item(j)).getAttribute("Type").endsWith("#SignedProperties")) {
								Element transformTag = (Element)((Element)referenceTag.item(j)).getElementsByTagNameNS(XMLSigner.XMLNS, "Transform").item(0);
								String canonString = transformTag.getAttribute("Algorithm");
								verifyDigest((Element)signatureListTags.item(i), digestMethod, digestValue, canonString);
							}
						}
						
					}
					Element signatureValueTag = getSignatureElement("SignatureValue", signatureTag, true);
					String signatureValue = signatureValueTag.getTextContent();
					Element keyInfoTag = getSignatureElement("KeyInfo", signatureTag, true);
					Element X509DataTag = getSignatureElement("X509Data", keyInfoTag, true);
					Element X509CertificateTag = getSignatureElement("X509Certificate", X509DataTag, true);
					String x509Certificate = X509CertificateTag.getTextContent();
					
					Element objectTag = getSignatureElement("Object", signatureTag, true);
					
					Element qualifyingPropertiesTag = getXadesElement("QualifyingProperties", objectTag, true);
					Element signedPropertiesTag = getXadesElement("SignedProperties", qualifyingPropertiesTag, true);
					Element signedSignaturePropertiesTag = getXadesElement("SignedSignatureProperties", signedPropertiesTag, true);
					Element signingTimeTag = getXadesElement("SigningTime", signedSignaturePropertiesTag, true);
					String signingTime = signingTimeTag.getTextContent();
					Element signingCertificateTag = getXadesElement("SigningCertificate", signedSignaturePropertiesTag, true);
					if(signingCertificateTag == null) {
						signingCertificateTag = getXadesElement("SigningCertificateV2", signedSignaturePropertiesTag, true);
					}
					Element certTag = getXadesElement("Cert", signingCertificateTag, true);
					Element certDigestTag = getXadesElement("CertDigest", certTag, true);
					Element digestMethodTag = getSignatureElement("DigestMethod", certDigestTag, true);
					String certDigestMethod = getAttribute(digestMethodTag, "Algorithm", true);
					Element digestValueTag = getSignatureElement("DigestValue", certDigestTag, true);
					String certDigestValue = digestValueTag.getTextContent();
					Element issuerSerialV2Tag = getXadesElement("IssuerSerialV2", certTag, true);
					Element signedDataObjectPropertiesTag = getXadesElement("SignedDataObjectProperties", signedPropertiesTag, true);
					Element dataObjectFormatTag = getXadesElement("DataObjectFormat", signedDataObjectPropertiesTag, true);
					Element mimeTypeTag = getXadesElement("MimeType", dataObjectFormatTag, true);
					Element signaturePolicyIdentifier = getXadesElement("SignaturePolicyIdentifier", qualifyingPropertiesTag, false);			
					if(signaturePolicyIdentifier != null) {
						getXadesElement("SigPolicyId", signaturePolicyIdentifier, false);
					}
					X509Certificate cert = null;
					try {
						cert = getCertificate(x509Certificate);
					} catch (CertificateException e) {
						validationErrors.add("Certificado inválido");
					}
					
					if(cert != null) {
						verifyHash(signatureTag, signatureInfoTag, signatureValue, cert);
						verifyPolicy(signatureTag, "2.16.76.1.7.1.6.2.3", signatureMethod, signatureValue);
					}
				}
			}
			
		
		} catch (ParserConfigurationException | SAXException | IOException e) {
			e.printStackTrace();
		}
		
		if(validationErrors.size() > 0) {
			System.out.println("Verification failed");
			for(String msg:validationErrors)
				System.out.println("Error: "+msg);
		}
		
		for(String msg : validationWaring)
			System.out.println("Waring: "+msg);
	}

}
