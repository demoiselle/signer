/*
 * Demoiselle Framework
 * Copyright (C) 2021 SERPRO
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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateRevocationException;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.validator.CRLValidator;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.impl.xades.XMLSignatureInformations;
import org.demoiselle.signer.policy.impl.xades.util.PolicyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * 
 * This implementation is based in XAdEs standard, available in https://www.w3.org/TR/XAdES/ and 
 * Brazilian digital signature standards presented 
 * in https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-15-03-versao-7-4-req-das-pol-de-assin-dig-na-icp-brasil-pdf  
 * 
 * @author Fabiano Kuss <fabiano.kuss@serpro.gov.br>
 * @author Emerson Saito <emerson.saito@serpro.gov.br>
 *
 */

public class XMLChecker {
	
	private static final Logger logger = LoggerFactory.getLogger(XMLChecker.class);
	private XMLSigner signer = new XMLSigner();
	private Date today = Calendar.getInstance().getTime();
	private boolean isDetached = false;
	private List<XMLSignatureInformations> signaturesInfo = new ArrayList<XMLSignatureInformations>();
	
	/**
	 * XML signature validation using file path. The file must contains both content and signature
	 *
	 * @param path to signed XML file. 
	 */
	
	public void check(byte[] docData) {
		Document doc = makeDocument(docData);
		verify(doc);
	}
	
	/**
	 * 
	 * XML signature validation using document. The file must contains both content and signature
	 * 
	 * @param DOM document
	 */
	public void check(Document doc) {
		verify(doc);
	}
	
	/**
	 * 
	 * * XML signature validation with detached file. 
	 * 
	 * @param file contents 
	 * @param XML String in byte[] format
	 */
	
	public void check(byte[] docData, byte[] signature) {
		check(makeDocument(signature));
	}
	
	/**
	 * /**
	 * 
	 * * XML signature validation with detached file. 
	 * 
	 * @param file content
	 * @param signature in Document class format
	 */
	
	public void check(byte[] docData, Document signature){
		isDetached = true;
		verify(signature);
		
		try {
						
			Element signatureInfoTag = getSignatureElement("SignedInfo", (Element)signature.getChildNodes().item(0), true);
			NodeList references = signatureInfoTag.getElementsByTagNameNS(XMLSigner.XMLNS, "Reference");
			for(int i=0;  i < references.getLength(); i++) {
				if(((Element)references.item(i)).getAttribute("Type").isEmpty()) {
					Element digestMethod = getSignatureElement("DigestMethod", ((Element)references.item(i)), true);
					Element digestValue =  getSignatureElement("DigestValue", ((Element)references.item(i)), true);
					String strAlg = AlgorithmsValues.getSignatureDigest(digestMethod.getAttribute("Algorithm"));
					String value = digestValue.getTextContent();
					
					if(!strAlg.isEmpty()) {
						MessageDigest messageDigest = MessageDigest.getInstance(strAlg);
						String hashValue =  Base64.toBase64String(messageDigest.digest(docData));
						
						if(!value.equals(hashValue)) {
							validationErrors.add("Resumo criptográfico do arquivo não corresponde ao da assinatura");
						}
					}else {
						validationErrors.add("algoritmo do resumo não informado");
					}
				}
			}
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add("Algoritmo criptográfico inválido");
		}
		
		if(validationErrors.size() > 0) {
			System.out.println("Verification failed");
			for(String msg:validationErrors)
				System.out.println("Error: "+msg);
		}
		
		for(String msg : validationWaring)
			System.out.println("Waring: "+msg);
	}
	
	
	
	LinkedList<String> validationErrors  = new LinkedList<String>();
	LinkedList<String> validationWaring  = new LinkedList<String>();
	
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
		if(parent == null) {
			validationErrors.add("Nó pai do elemento: "+tagName+ " não encontrado");
			return null;
		}
		if(tagName == null) {
			validationErrors.add("Nome de elemento inválido para o nó "+parent.getTagName());
			return null;
		}
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
				if(AlgorithmsValues.isCanonicalMethods(((Element)transformTag.item(j)).getAttribute("Algorithm"))) {
					xPathTransformAlgorithm = ((Element)transformTag.item(j)).getAttribute("Algorithm");
					break;
				}
			}
		}
		
		if(xPathTransformAlgorithm.isEmpty()) {
			validationErrors.add("Algoritmo de canonização inválido");
		}
		
		try {
			Element docData = signer.getDocumentData(doc);
			byte[] docHash = signer.getShaCanonizedValue(AlgorithmsValues.getSignatureDigest(digestMethod), docData, xPathTransformAlgorithm);
			if(!Base64.toBase64String(docHash).equals(digestValue)) {
				validationErrors.add("Resumo criptográfico não confere com o conteúdo do documento");
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
			validationErrors.add("algoritmo de assinatura inválido ou não suportado");
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
	
	public void verifyCertificate(X509Certificate varCert) {
		CRLValidator cV = new CRLValidator();				
		try {
			cV.validate(varCert);	
		}catch (CertificateValidatorCRLException cvce) {
			validationErrors.add(cvce.getMessage());
			logger.info(cvce.getMessage());
		}catch (CertificateRevocationException cre) {
			validationErrors.add(cre.getMessage());
			logger.info("certificado revogado");
		}
		
		PeriodValidator pV = new PeriodValidator();				
		try{
			pV.valDate(varCert);			
		}catch (CertificateValidatorException cve) {
			validationWaring.add(cve.getMessage());
		}
					
	}
	
	private Document verifyPolicy(Element signature, String policyOID, String signatureMethod, String signatureValue) {
		boolean isValidAlgorithm = false;
		if(policyOID == null) {
			validationWaring.add("Identificação da política nula");
		}
		Document doc = PolicyFactory.getInstance().loadXMLPolicy(PolicyUtils.getPolicyByOid(policyOID));
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
			DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
			Date dateBefore = null;
			Date dateAfter = null;
			
			Element notBefore = getElement("pa:NotBefore", (Element)signingPeriod.item(0));
			Element notAfter = getElement("pa:NotAfter", (Element)signingPeriod.item(0));
			
			try {
				dateBefore = (Date)formatter.parse(notBefore.getTextContent());
				dateAfter = (Date)formatter.parse(notAfter.getTextContent());
				if(dateBefore.getTime() > today.getTime()) {
					validationWaring.add("Inicio da politica maior que a data atual");
				}
				if(dateAfter.getTime() < today.getTime()) {
					validationWaring.add("Data de fim da politica maior que a a data atual");
				}
			} catch (ParseException e) {
				validationWaring.add("Formato da data de validade da política inválido");
			}
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
		
		return doc;
		
		
	}
	
	public Document makeDocumentByFile(String fileName) {
		File fXmlFile = new File(fileName);
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		DocumentBuilder dBuilder;
		try {
			dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(fXmlFile);
			return doc;
		}catch (ParserConfigurationException | SAXException | IOException e) {
			return null;
		}
	}
	
	private Document makeDocument(byte[] signature) {
	
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		DocumentBuilder dBuilder;
		try {
			dBuilder = dbFactory.newDocumentBuilder();
			Document doc = dBuilder.parse(new ByteArrayInputStream(signature));
			return doc;
		}catch (ParserConfigurationException | SAXException | IOException e) {
			return null;
		}
	}
	
	public void verifySignature(Element signature, X509Certificate cert) {
		
		try {
				
			Element canonicalizationMethodTag = getSignatureElement("CanonicalizationMethod", signature, true);
			Element signatureMethodTag = getSignatureElement("SignatureMethod", signature, true);
			Element signatureValueTag = getSignatureElement("SignatureValue", signature, true);
			String canonicalizationMethod = getAttribute(canonicalizationMethodTag, "Algorithm", true);
			String signatureMethod = AlgorithmsValues.getSignatureAlgorithm(getAttribute(signatureMethodTag, "Algorithm", true));
			
			Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			
			byte[] dh = c14n.canonicalizeSubtree(signature.getElementsByTagName("ds:SignedInfo").item(0));
			byte[] sigValue = Base64.decode(signatureValueTag.getTextContent());
			
			if(!AlgorithmsValues.isCanonicalMethods(canonicalizationMethod)) {
				validationErrors.add("algoritmo de canonização inválido");
			}
			
			Signature sig = Signature.getInstance(signatureMethod);
			sig.initVerify(cert);
			sig.update(dh);
			if(!sig.verify(sigValue)) {
				validationErrors.add("Resumo da assinatura não confere");
			}
			
		} catch (InvalidCanonicalizerException e) {
			validationErrors.add("Erro no algoritmo de canonização");
		} catch (CanonicalizationException e) {
			validationErrors.add("Erro no algoritmo de canonização");
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add("Erro no algoritmo criptográfico da assinatura");
		} catch (InvalidKeyException e) {
			validationErrors.add("Chave criptográfica inválida");
		} catch (SignatureException e) {
			validationErrors.add("Erro ao verificar a assinatura: "+e.getMessage());
		}
		
	}
	
	public boolean isDetachedFile(Document doc) {
		NodeList signatureListTags = doc.getElementsByTagNameNS(XMLSigner.XMLNS, "Signature");
		if(doc.getChildNodes().item(0) == signatureListTags.item(0))
			return true;
		return false;
	}
	
	private void verify(Document doc) {
		
		NodeList root = doc.getChildNodes();
		
		NodeList signatureListTags = doc.getElementsByTagNameNS(XMLSigner.XMLNS, "Signature");
		
		if(root.item(0) == signatureListTags.item(0)) {
			if(!isDetached) {
				validationErrors.add("A validação da assinatura depende do arquivo que tem que ser verificado");
			}
		}
		
		if(signatureListTags.getLength() < 0) {
			validationErrors.add("O documento não contém assinatura");
			return;
		}else {
			for(int i = 0; i < signatureListTags.getLength(); i++) {
				
				XMLSignatureInformations sigInf =  new XMLSignatureInformations();
				 
				Element signatureTag = (Element)signatureListTags.item(i);
				Element signatureInfoTag = getSignatureElement("SignedInfo", signatureTag, true);
				
				
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
				
				Element signedTime = getXadesElement("SigningTime", signedSignaturePropertiesTag, true);
				if(signedTime == null) {
					validationWaring.add("Elemento SigningTime não encontrado na assinatura");
				}else {
					DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
					try {
						sigInf.setSignDate(formatter.parse(signedTime.getTextContent()));
					} catch (DOMException | ParseException e) {
						validationWaring.add("Data mal formatada no elemento SigningTime");
					}
				}
				
				Element signingCertificateTag = getXadesElement("SigningCertificate", signedSignaturePropertiesTag, true);
				if(signingCertificateTag == null) {
					signingCertificateTag = getXadesElement("SigningCertificateV2", signedSignaturePropertiesTag, true);
				}
				Element certTag = getXadesElement("Cert", signingCertificateTag, true);
				Element certDigestTag = getXadesElement("CertDigest", certTag, true);
				
				if(getSignatureElement("DigestMethod", certDigestTag, true) == null)
					validationErrors.add("Elemento DigestMethod no elemento Cert não encontrado na assinatura");
				
				if(getSignatureElement("DigestValue", certDigestTag, true) == null)
					validationErrors.add("Elemento IssuerSerial no elemento Cert não encontrado na assinatura");
				
				if(getXadesElement("IssuerSerial", certTag, true) == null) {
					validationErrors.add("Elemento DigestValue no elemento Cert não encontrado na assinatura");
				}
				Element signedDataObjectPropertiesTag = getXadesElement("SignedDataObjectProperties", signedPropertiesTag, true);
				if(signedDataObjectPropertiesTag == null)
					validationErrors.add("Elemento SignedDataObjectProperties não encontrado na assinatura");
				//Element dataObjectFormatTag = getXadesElement("DataObjectFormat", signedDataObjectPropertiesTag, true);
				//Element mimeTypeTag = getXadesElement("MimeType", dataObjectFormatTag, true);
				Element signaturePolicyIdentifier = getXadesElement("SignaturePolicyIdentifier", qualifyingPropertiesTag, false);			
				Element sigPolicyId = null;
				if(signaturePolicyIdentifier != null) {
					sigPolicyId = getXadesElement("SigPolicyId", signaturePolicyIdentifier, false);
				}
				X509Certificate cert = null;
				try {
					cert = getCertificate(x509Certificate);
				} catch (CertificateException e) {
					validationErrors.add("Certificado inválido");
				}
				
				if(cert != null) {
					verifyCertificate(cert);
					verifySignature(signatureTag, cert);
					verifyHash(signatureTag, signatureInfoTag, signatureValue, cert);
				
					LinkedList<X509Certificate> varChain = (LinkedList<X509Certificate>)  CAManager.getInstance().getCertificateChain(cert);
					sigInf.setIcpBrasilcertificate(new BasicCertificate(cert));
					sigInf.setChain(varChain);
					sigInf.setNotAfter(cert.getNotAfter());
					
					if(sigPolicyId != null) {
						String signatureMethod = "";
						Element signatureMethodTag = getSignatureElement("SignatureMethod", signatureTag, true);
						if(signatureMethodTag != null) {
							signatureMethod = getAttribute(signatureMethodTag, "Algorithm", true);
						}
						
						Element sigPolicyIdIdentifier = getXadesElement("Identifier", sigPolicyId, true);
						if(sigPolicyIdIdentifier  != null) {
							String strIdentifier = sigPolicyIdIdentifier.getTextContent();
							Document docPolicy = verifyPolicy(signatureTag, strIdentifier, signatureMethod, signatureValue);
							sigInf.setSignaturePolicy(docPolicy);
						}
					}
				}
				
				sigInf.setValidatorErrors(validationErrors);
				sigInf.setValidatorWarnins(validationWaring);
				signaturesInfo.add(sigInf);
			}
		}
	}
	
	public List<XMLSignatureInformations> getSignaturesInfo() {
		return signaturesInfo;
	}
	
}
