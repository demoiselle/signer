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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
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
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.xml.icpb.XMLPolicyValidator;
import org.demoiselle.signer.policy.impl.xades.SignaturePack;
import org.demoiselle.signer.policy.impl.xades.XMLPoliciesOID;
import org.demoiselle.signer.policy.impl.xades.XMLSignerException;
import org.demoiselle.signer.policy.impl.xades.util.PolicyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * 
 * This implementation is based in XAdEs standard, available in
 * https://www.w3.org/TR/XAdES/ and Brazilian digital signature standards
 * presented in
 * https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-15-03-versao-7-4-req-das-pol-de-assin-dig-na-icp-brasil-pdf
 * 
 * @author Fabiano Kuss <fabiano.kuss@serpro.gov.br>
 * @author Emerson Saito <emerson.saito@serpro.gov.br>
 *
 */

public class XMLSigner {

	private PrivateKey privateKey = null;
	private PrivateKey privateKeyToTimestamp = null;
	private byte[] docSignature = null;
	private X509Certificate certificate;
	private Certificate certificateChain[] = null;
	private Certificate certificateChainToTimestamp[] = null;	
	private Document signedDocument = null;
	private String policyOID = "";
	private String id = "id-" + System.currentTimeMillis();
	private SignaturePack sigPack;
	private PolicyFactory.Policies policy;
	public static final String XMLNS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";
	private static final Logger logger = LoggerFactory.getLogger(XMLSigner.class);
	private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
	private Date notAfterSignerCertificate;

	public XMLSigner() {
		this.policyOID = XMLPoliciesOID.AD_RB_XADES_2_4.getOID();
		this.policy = PolicyUtils.getPolicyByOid(policyOID);
	}

	/**
	 * To set another policy @see PolicyUtils
	 * @param policyOID
	 */
	public void setPolicyId(String policyOID) {
		this.policyOID = policyOID;
		this.policy = PolicyUtils.getPolicyByOid(policyOID);
	}

	public Element getDocumentData(Document doc) throws XMLSignerException{

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder;
		Document bodyDoc = null;
		try {
			builder = dbf.newDocumentBuilder();
			dbf.setNamespaceAware(true);
			bodyDoc = builder.newDocument();
			Node body = bodyDoc.importNode(doc.getDocumentElement(), true);
			bodyDoc.appendChild(body);
			NodeList signatures = bodyDoc.getElementsByTagName("ds:Signature");
			for (int i = 0; i < signatures.getLength(); i++)
				signatures.item(i).getParentNode().removeChild(signatures.item(i));
		} catch (ParserConfigurationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
		}		
		return bodyDoc.getDocumentElement();	
	}

	public byte[] getShaCanonizedValue(String alg, Node xml, String canonical) throws XMLSignerException{
		Init.init();
		Canonicalizer c14n;
		try {
			c14n = Canonicalizer.getInstance(canonical);
		} catch (InvalidCanonicalizerException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(alg);
		} catch (NoSuchAlgorithmException e) {
			logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
		}
		try {
			return messageDigest.digest(c14n.canonicalizeSubtree(xml));
		} catch (CanonicalizationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}
	}

	private String getCertificateDigest(X509Certificate cert, String algorithm) throws XMLSignerException {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] digestValue = md.digest(cert.getEncoded());
			return Base64.toBase64String(digestValue);
		} catch (Exception e) {
			logger.error(xadesMessagesBundle.getString("error.cert.digest"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.cert.digest"));
			
		}
	}

	/*
	 * private String getIssuerSerialV2(X509Certificate cert) throws IOException {
	 * X500Name issuerX500Name = null; try { issuerX500Name = new
	 * X509CertificateHolder(cert.getEncoded()).getIssuer(); } catch
	 * (CertificateEncodingException e) { e.printStackTrace(); } catch (IOException
	 * e) { e.printStackTrace(); } final GeneralName generalName = new
	 * GeneralName(issuerX500Name); final GeneralNames generalNames = new
	 * GeneralNames(generalName); final BigInteger serialNumber =
	 * cert.getSerialNumber(); final IssuerSerial issuerSerial = new
	 * IssuerSerial(generalNames, serialNumber);
	 * 
	 * return
	 * Base64.toBase64String(issuerSerial.toASN1Primitive().getEncoded(ASN1Encoding.
	 * DER)); }
	 */

	private Element addPolicy(Document doc) throws XMLSignerException{

		String hash = "";

		Document policyDoc = null;
		Element policyIdentifier = null;
		policyDoc = PolicyFactory.getInstance().loadXMLPolicy(policy);
		NodeList listHash = policyDoc.getElementsByTagName("pa:SignPolicyDigest");
		if (listHash.getLength() > 0) {
			hash = listHash.item(0).getTextContent();
		}
		policyIdentifier = (Element) policyDoc.getElementsByTagName("XAdES:Identifier").item(0);

		Element sigPolicyIdentifier = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyIdentifier");

		Element sigPolicyId = doc.createElementNS(XAdESv1_3_2, "xades:SignaturePolicyId");
		sigPolicyIdentifier.appendChild(sigPolicyId);

		Element sigPId = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyId");
		sigPolicyId.appendChild(sigPId);

		Element identifier = doc.createElementNS(XAdESv1_3_2, "xades:Identifier");
		identifier.setAttribute("Qualifier", "OIDAsURN");
		identifier.setTextContent(policyIdentifier.getTextContent());
		sigPId.appendChild(identifier);

		Element sigTransforms = doc.createElementNS(XMLNS, "ds:Transforms");
		sigPolicyId.appendChild(sigTransforms);

		Element sigTransform = doc.createElementNS(XMLNS, "ds:Transform");
		sigTransform.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

		sigTransforms.appendChild(sigTransform);

		Element sigPolicyHash = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyHash");
		sigPolicyId.appendChild(sigPolicyHash);

		Element sigDigestMethod = doc.createElementNS(XMLNS, "ds:DigestMethod");
		sigDigestMethod.setAttribute("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256");
		sigPolicyHash.appendChild(sigDigestMethod);

		Element sigDigestValue = doc.createElementNS(XMLNS, "ds:DigestValue");
		sigDigestValue.setTextContent(hash);
		sigPolicyHash.appendChild(sigDigestValue);

		Element sigPolicyQualifiers = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyQualifiers");
		sigPolicyId.appendChild(sigPolicyQualifiers);

		Element sigPolicyQualifier = doc.createElementNS(XAdESv1_3_2, "xades:SigPolicyQualifier");
		sigPolicyQualifiers.appendChild(sigPolicyQualifier);

		Element sigSPURI = doc.createElementNS(XAdESv1_3_2, "xades:SPURI");
		sigSPURI.setTextContent(policy.getUrl());
		sigPolicyQualifier.appendChild(sigSPURI);

		return sigPolicyIdentifier;
	}

	private Element signedObject(X509Certificate cert, Document doc) {

		Element sigObject = doc.createElementNS(XMLNS, "ds:Object");

		Element sigQualify = doc.createElementNS(XAdESv1_3_2, "xades:QualifyingProperties");
		sigQualify.setAttribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
		sigQualify.setAttribute("Target", "#" + id);
		sigObject.appendChild(sigQualify);

		Element sigProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedProperties");
		sigProp.setAttribute("Id", "xades-" + id);
		sigQualify.appendChild(sigProp);

		Element sigSignedProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedSignatureProperties");
		sigProp.appendChild(sigSignedProp);

		Element sigTime = doc.createElementNS(XAdESv1_3_2, "xades:SigningTime");
		SimpleDateFormat sdt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
		String signDate = sdt.format(Calendar.getInstance().getTime());
		sigTime.setTextContent(signDate + "Z");
		sigSignedProp.appendChild(sigTime);

		Element sigCertV2 = doc.createElementNS(XAdESv1_3_2, "xades:SigningCertificate");
		sigSignedProp.appendChild(sigCertV2);

		Element sigCert = doc.createElementNS(XAdESv1_3_2, "xades:Cert");
		sigCertV2.appendChild(sigCert);

		Element sigCertDig = doc.createElementNS(XAdESv1_3_2, "xades:CertDigest");
		sigCert.appendChild(sigCertDig);

		Element sigDigMet = doc.createElementNS(XMLNS, "ds:DigestMethod");
		sigDigMet.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha1");
		sigCertDig.appendChild(sigDigMet);

		Element sigDigValue = doc.createElementNS(XMLNS, "ds:DigestValue");
		sigDigValue.setTextContent(getCertificateDigest(cert, "SHA1"));
		sigCertDig.appendChild(sigDigValue);

		Element sigIssuerSerial = doc.createElementNS(XAdESv1_3_2, "xades:IssuerSerial");
		// sigIssuerSerial.setTextContent(getIssuerSerialV2(cert));
		sigCert.appendChild(sigIssuerSerial);

		String issuerName = cert.getIssuerX500Principal().toString();
		String serialId = cert.getSerialNumber().toString();

		// Element sigIssuerSeria = doc.createElementNS(XAdESv1_3_2,
		// "xades:IssuerSerialV2");
		// sigIssuerSerial.setTextContent(getIssuerSerialV2(cert));
		// sigCert.appendChild(sigIssuerSerial);

		Element sigIssuerName = doc.createElementNS(XMLNS, "ds:X509IssuerName");
		sigIssuerName.setTextContent(issuerName);
		sigIssuerSerial.appendChild(sigIssuerName);

		Element sigIssuerNumber = doc.createElementNS(XMLNS, "ds:X509SerialNumber");
		sigIssuerNumber.setTextContent(serialId);
		sigIssuerSerial.appendChild(sigIssuerNumber);

		if (!policyOID.isEmpty()) {
			sigSignedProp.appendChild(addPolicy(doc));
		}

		Element sigSigDataObjeProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedDataObjectProperties");
		sigProp.appendChild(sigSigDataObjeProp);

		Element sigDataObjFormat = doc.createElementNS(XAdESv1_3_2, "xades:DataObjectFormat");
		sigDataObjFormat.setAttribute("ObjectReference", "#r-id-1");
		sigSigDataObjeProp.appendChild(sigDataObjFormat);

		/*
		 * Element sigDescription = doc.createElementNS(XAdESv1_3_2,
		 * "xades:Description"); sigDescription.setTextContent(doc.getBaseURI());
		 * sigDataObjFormat.appendChild(sigDescription);
		 */

		Element sigMimeType = doc.createElementNS(XAdESv1_3_2, "xades:MimeType");
		sigMimeType.setTextContent("text/xml");
		sigDataObjFormat.appendChild(sigMimeType);

		return sigObject;

	}

	public Element createSignatureHashReference(Document doc, byte[] signedTagData) throws XMLSignerException {

		HashMap<String, String> param = new HashMap<String, String>();
		param.put("type", Constants.SignedProperties);
		param.put("uri", "#xades-" + id);
		param.put("alg", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

		param.put("digAlg", "http://www.w3.org/2001/04/xmlenc#sha256");

		MessageDigest md = null;

		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
		}

		byte[] digestValue = md.digest(signedTagData);
		param.put("digVal", Base64.toBase64String(digestValue));

		return createReferenceTag(doc, param);
	}

	private Element createReferenceTag(Document doc, HashMap<String, String> params) {

		Element referenceTag = doc.createElementNS(XMLNS, "ds:Reference");
		if (params.containsKey("id")) {
			referenceTag.setAttribute("Id", params.get("id"));
		}
		referenceTag.setAttribute("Type", params.get("type"));
		referenceTag.setAttribute("URI", params.get("uri"));
		// sigInfTag.appendChild(referenceTag );

		if (!params.containsKey("no_transforms")) {
			Element transformsTag = doc.createElementNS(XMLNS, "ds:Transforms");
			referenceTag.appendChild(transformsTag);

			if (params.containsKey("alg")) {
				Element transformTag = doc.createElementNS(XMLNS, "ds:Transform");
				transformTag.setAttribute("Algorithm", params.get("alg"));
				transformsTag.appendChild(transformTag);
				if (params.containsKey("text")) {
					Element xPathTag = doc.createElementNS(XMLNS, "ds:XPath");
					xPathTag.setTextContent(params.get("text"));
					transformTag.appendChild(xPathTag);
				}
			}

			if (params.containsKey("transAlg")) {
				Element transAlg = doc.createElementNS(XMLNS, "ds:Transform");
				transAlg.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
				transformsTag.appendChild(transAlg);
			}
		}

		if (params.containsKey("digAlg")) {
			Element digMethodTag = doc.createElementNS(XMLNS, "ds:DigestMethod");
			digMethodTag.setAttribute("Algorithm", params.get("digAlg"));
			referenceTag.appendChild(digMethodTag);

			digMethodTag = doc.createElementNS(XMLNS, "ds:DigestValue");
			digMethodTag.setTextContent(params.get("digVal"));
			referenceTag.appendChild(digMethodTag);
		}

		return referenceTag;
	}

	private Document buildXML(String fileName) throws XMLSignerException {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document bodyDoc = null;

		if (sigPack == SignaturePack.DETACHED) {
			try {
				bodyDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			} catch (ParserConfigurationException e) {
				logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
				throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			}
		} else {
			try {
				bodyDoc = dbf.newDocumentBuilder()
						.parse(new InputSource(new InputStreamReader(new FileInputStream(fileName), "UTF-8")));
			} catch (SAXException | IOException | ParserConfigurationException e) {
				logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
				throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			}
		}

		Element signatureTag = bodyDoc.createElementNS(XMLNS, "ds:Signature");
		signatureTag.setAttributeNS("http://www.w3.org/2000/xmlns/", XMLNS_DS, XMLNS);
		signatureTag.setAttributeNS("http://www.w3.org/2000/xmlns/", XMLNS_XADES, XAdESv1_3_2);
		signatureTag.setAttribute("Id", id);

		Element sigInfTag = bodyDoc.createElementNS(XMLNS, "ds:SignedInfo");
		signatureTag.appendChild(sigInfTag);

		Element canonicalizationMethodTag = bodyDoc.createElementNS(XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		// canonicalizationMethodTag.setAttribute("Algorithm",
		// "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

		sigInfTag.appendChild(canonicalizationMethodTag);

		Element signatureMethodTag = bodyDoc.createElementNS(XMLNS, "ds:SignatureMethod");
		signatureMethodTag.setAttribute("Algorithm", Constants.RSA_SHA256);
		sigInfTag.appendChild(signatureMethodTag);

		HashMap<String, String> param = new HashMap<String, String>();
		param.put("type", "");
		param.put("uri", "");
		param.put("id", "r-id-1");
		param.put("text", "not(ancestor-or-self::ds:Signature)");
		param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
		param.put("digAlg", Constants.DIGEST_SHA256);

		byte[] docHash = null;

		if (sigPack == SignaturePack.DETACHED) {
			InputStream inputStream;
			try {
				inputStream = new FileInputStream(fileName);
			} catch (FileNotFoundException e) {	
				logger.error(xadesMessagesBundle.getString("error.file.not.found", fileName));
				throw new XMLSignerException(xadesMessagesBundle.getString("error.file.not.found", fileName));
				
			}
			long fileSize = new File(fileName).length();
			docHash = new byte[(int) fileSize];			
			try {
				inputStream.read(docHash);
				inputStream.close();
			} catch (IOException e) {
				logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
				throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
				
			}
			param.put("no_transforms", "true");
			param.put("type", "");
			param.put("uri", Paths.get(fileName).getFileName().toString());
			MessageDigest messageDigest= null;
			try {
				messageDigest = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
				throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			}
			param.put("digVal", Base64.toBase64String(messageDigest.digest(docHash)));

			Element referenceTag = createReferenceTag(bodyDoc, param);
			sigInfTag.appendChild(referenceTag);

			bodyDoc.appendChild(signatureTag);

		} else {
			Element docData = getDocumentData(bodyDoc);
			docHash = getShaCanonizedValue("SHA-256", docData, Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
			param.put("type", "");
			param.put("uri", "");
			param.put("id", "r-id-1");
			param.put("text", "not(ancestor-or-self::ds:Signature)");
			param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
			param.put("digAlg", Constants.DIGEST_SHA256);
			param.put("transAlg", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

			param.put("digVal", Base64.toBase64String(docHash));

			Element referenceTag = createReferenceTag(bodyDoc, param);
			sigInfTag.appendChild(referenceTag);

			bodyDoc.getDocumentElement().appendChild(signatureTag);

		}

		return bodyDoc;
	}

	private Element createUnsignedProperties(Document doc, List<String> parmProperties) throws XMLSignerException{

		Element unsignedProperties = doc.createElementNS(XAdESv1_3_2, "xades:UnsignedProperties");
		Element unsignedSignatureProperties = doc.createElementNS(XAdESv1_3_2, "xades:UnsignedSignatureProperties");
		unsignedProperties.appendChild(unsignedSignatureProperties);
		for (String propertie : parmProperties) {
			Element unsignedSignaturePropertie = null;
			switch (propertie) {
				case "SignatureTimeStamp":
					unsignedSignaturePropertie = createSignatureTimeStampPropertie(doc);
					break;
				case "CompleteCertificateRefs":
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					// break;
				case "CompleteRevocationRefs":
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					// break;
				case "SigAndRefsTimeStamp":
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					// break;
				case "CertificateValues":
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					// 	break;
				case "RevocationValues":
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					// break;
				case "ArchiveTimeStamp":
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					// break;
				default:
					logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
					throw new XMLSignerException(
						xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				}
			unsignedSignatureProperties.appendChild(unsignedSignaturePropertie);
		}
		return unsignedProperties;

	}

	private Element createSignatureTimeStampPropertie(Document doc) {

		Element signatureTimeStamp = doc.createElement("xades:SignatureTimeStamp");
		Element canonicalizationMethodTag = doc.createElementNS(XMLNS, "ds:CanonicalizationMethod");
		// canonicalizationMethodTag.setAttribute("Algorithm","http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
		signatureTimeStamp.appendChild(canonicalizationMethodTag);
		Element encapsulatedTimeStamp = doc.createElement("xades:EncapsulatedTimeStamp");
		encapsulatedTimeStamp.setAttribute("Id", "TimeStamp" + id);
		XMLTimeStampToken varXMLTimeStampToken = new XMLTimeStampToken(getPrivateKeyToTimestamp(), getCertificateChainToTimestamp(), docSignature, null);
		String timeStampContent = Base64.toBase64String(varXMLTimeStampToken.getTimeStampToken());
		encapsulatedTimeStamp.setTextContent(timeStampContent);
		signatureTimeStamp.appendChild(encapsulatedTimeStamp);
		return signatureTimeStamp;
	}

	/**
	 * Sign a XML file, from String with File Name and location. (ex: .sign("/tmp/file.xml");
	 * @param fileNameSource
	 * @return Document 
	 * @throws XMLSignerException
	 */
	public Document sign(String fileNameSource) throws XMLSignerException {
		
		if (fileNameSource == null || fileNameSource.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.file.null"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.file.null"));
		}
		
		Document policyDoc;
		policyDoc = PolicyFactory.getInstance().loadXMLPolicy(policy);
		
		XMLPolicyValidator xMLPolicyValidator = new XMLPolicyValidator(policyDoc);

		if (!xMLPolicyValidator.validate()) {
			logger.error(xadesMessagesBundle.getString("error.policy.not.recognized",policyDoc.getDocumentURI()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.policy.not.recognized",policyDoc.getDocumentURI()));
		}
		Init.init();

		Document doc = buildXML(fileNameSource);

		if (this.certificateChain == null) {
			logger.error(xadesMessagesBundle.getString("error.certificate.null"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.certificate.null"));
		}

		if (getPrivateKey() == null) {
			logger.error(xadesMessagesBundle.getString("error.privatekey.null"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.privatekey.null"));
		}

		// Completa os certificados ausentes da cadeia, se houver
		if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
			this.certificate = (X509Certificate) this.certificateChain[0];
		}

		this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);

		if (this.certificateChain.length < 3) {
			logger.error(xadesMessagesBundle.getString("error.no.ca", this.certificate.getIssuerDN()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.ca", this.certificate.getIssuerDN()));
		}

		PeriodValidator pV = new PeriodValidator();
		setNotAfterSignerCertificate(pV.valDate(this.certificate));

		int numSignatures = doc.getElementsByTagName("ds:Signature").getLength() - 1;

		Element sigTag = (Element) doc.getElementsByTagName("ds:Signature").item(numSignatures);

		Element objectTag = signedObject(certificate, doc);

		Init.init();
		Canonicalizer c14n;
		try {
			c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE);
		} catch (InvalidCanonicalizerException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}

		byte[] canonicalized = null;

		try {
			canonicalized = c14n.canonicalizeSubtree(objectTag.getElementsByTagName("xades:SignedProperties").item(0));
		} catch (CanonicalizationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}

		Element sigRefTag = createSignatureHashReference(doc, canonicalized);
		doc.getElementsByTagName("ds:SignedInfo").item(numSignatures).appendChild(sigRefTag);

		try {
			c14n = Canonicalizer.getInstance(CanonicalizationMethod.INCLUSIVE);
		} catch (InvalidCanonicalizerException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}
		byte[] dh;
		try {
			dh = c14n.canonicalizeSubtree(doc.getElementsByTagName("ds:SignedInfo").item(numSignatures));
		} catch (CanonicalizationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}

		Signature sig;
		try {
			sig = Signature.getInstance("SHA256withRSA");
		} catch (NoSuchAlgorithmException e) {
			logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
		}
		try {
			sig.initSign(privateKey);
		} catch (InvalidKeyException e) {
			logger.error(xadesMessagesBundle.getString("error.private.key.invalid"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.private.key.invalid"));
		}
		try {
			sig.update(dh);
			docSignature = sig.sign();
		} catch (SignatureException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));
			
		}

		Element signValueTag = doc.createElementNS(XMLNS, "ds:SignatureValue");
		signValueTag.setAttribute("Id", "value-" + id);
		String hash = Base64.toBase64String(docSignature);
		String result = hash;

		signValueTag.setTextContent(result);
		sigTag.appendChild(signValueTag);

		Element keyInfo = doc.createElementNS(XMLNS, "ds:KeyInfo");
		doc.getElementsByTagName("ds:Signature").item(numSignatures).appendChild(keyInfo);

		Element x509 = doc.createElementNS(XMLNS, "ds:X509Data");
		keyInfo.appendChild(x509);

		Element X509SubjectName = doc.createElementNS(XMLNS, "ds:X509SubjectName");
		X509SubjectName.setTextContent(certificate.getSubjectDN().getName());
		x509.appendChild(X509SubjectName);

		Element x509Certificate = doc.createElementNS(XMLNS, "ds:X509Certificate");
		try {
			x509Certificate.setTextContent(Base64.toBase64String(certificate.getEncoded()));
		} catch (CertificateEncodingException | DOMException e) {
			logger.error(xadesMessagesBundle.getString("error.cert.digest"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.cert.digest"));
		}
		x509.appendChild(x509Certificate);

		
		NodeList listMandetedUnsignedProperties = policyDoc.getElementsByTagName("pa:MandatedUnsignedQProperties");
		if (listMandetedUnsignedProperties.getLength() > 0) {
			if (getPrivateKeyToTimestamp() == null) {
				setPrivateKeyToTimestamp(getPrivateKey());
			}
			if (getCertificateChainToTimestamp() ==null) {
				setCertificateChainToTimestamp(getCertificateChain());
			}
			List<String> valuesMandetedUnsignedProperties = new ArrayList<String>();
			for (int i = 0; i < listMandetedUnsignedProperties.getLength(); i++) {
				Element mandetedUnsignedElement = (Element) listMandetedUnsignedProperties.item(i);
				NodeList childNodeList = mandetedUnsignedElement.getChildNodes();
				for (int j = 0; j < childNodeList.getLength(); j++) {
					Node chileNode = childNodeList.item(j);
					valuesMandetedUnsignedProperties.add(chileNode.getTextContent());
				}
			}
			Element unsignedProperties = createUnsignedProperties(doc, valuesMandetedUnsignedProperties);
			objectTag.getElementsByTagName("xades:QualifyingProperties").item(0).appendChild(unsignedProperties);
		}

		sigTag.appendChild(objectTag);

		signedDocument = doc;

		return doc;
	}

	public void saveSignedDocument(String fileName) throws TransformerException, FileNotFoundException {
		OutputStream os = new FileOutputStream(fileName);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(signedDocument), new StreamResult(os));
	}

	public void setSignaturePackaging(SignaturePack pack) {
		sigPack = pack;

	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	public Certificate[] getCertificateChain() {
		return certificateChain;
	}

	public void setCertificateChain(Certificate certificateChain[]) {
		this.certificateChain = certificateChain;
	}

	public Date getNotAfterSignerCertificate() {
		return notAfterSignerCertificate;
	}

	public void setNotAfterSignerCertificate(Date notAfterSignerCertificate) {
		this.notAfterSignerCertificate = notAfterSignerCertificate;
	}

	public PrivateKey getPrivateKeyToTimestamp() {
		return privateKeyToTimestamp;
	}

	public void setPrivateKeyToTimestamp(PrivateKey privateKeyToTimestamp) {
		this.privateKeyToTimestamp = privateKeyToTimestamp;
	}

	public Certificate[] getCertificateChainToTimestamp() {
		return certificateChainToTimestamp;
	}

	public void setCertificateChainToTimestamp(Certificate certificateChainToTimestamp[]) {
		this.certificateChainToTimestamp = certificateChainToTimestamp;
	}

}
