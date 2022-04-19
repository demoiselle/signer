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

package org.demoiselle.signer.policy.impl.xades.xml.impl;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.xml.icpb.XMLPolicyValidator;
import org.demoiselle.signer.policy.impl.xades.XMLPoliciesOID;
import org.demoiselle.signer.policy.impl.xades.XMLSignerException;
import org.demoiselle.signer.policy.impl.xades.util.DocumentUtils;
import org.demoiselle.signer.policy.impl.xades.util.PolicyUtils;
import org.demoiselle.signer.policy.impl.xades.xml.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This implementation is based in XAdEs standard, available in
 * https://www.w3.org/TR/XAdES/ and Brazilian digital signature standards
 * presented in
 * https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-15-03-versao-7-4-req-das-pol-de-assin-dig-na-icp-brasil-pdf
 *
 * @author Fabiano Kuss &lt;fabiano.kuss@serpro.gov.br&gt;
 * @author Emerson Saito &lt;emerson.saito@serpro.gov.br&gt;
 */
public class XMLSigner implements Signer {

	public static final String XMLNS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";
	private static final Logger logger = LoggerFactory.getLogger(XMLSigner.class);
	private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
	private PrivateKey privateKey = null;
	private PrivateKey privateKeyToTimestamp = null;
	private byte[] docSignature = null;
	private X509Certificate certificate;
	private Certificate certificateChain[] = null;
	private Certificate certificateChainToTimestamp[] = null;
	private Document signedDocument = null;
	private String policyOID = "";
	private String id = "id-" + System.currentTimeMillis();
	private boolean detachedSignaturePack = false;
	private String detachedFileName = null;
	private PolicyFactory.Policies policy;
	private Date notAfterSignerCertificate;
	private String signatureAlgorithm = "SHA256withRSA";
	private String signatureDigest = "SHA-256";
	

	public XMLSigner() {
		this.policyOID = XMLPoliciesOID.AD_RB_XADES_2_4.getOID();
		this.policy = PolicyUtils.getPolicyByOid(policyOID);
	}

	/**
	 * To set another policy @see PolicyUtils.
	 *
	 * @param policyOID the policy OID.
	 */
	public void setPolicyId(String policyOID) {
		this.policyOID = policyOID;
		this.policy = PolicyUtils.getPolicyByOid(policyOID);
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
		setSignatureDigest(AlgorithmsValues.getdigestTosignature(signatureAlgorithm));
	}

	public String getSignatureDigest() {
		return signatureDigest;
	}

	private void setSignatureDigest(String signatureDigest) {
		this.signatureDigest = signatureDigest;
	}

	/**
	 * Sign an XML file, from File Name and location.
	 *
	 * @param isFileLocation indicates the next parameter is a fileLocation.
	 * @param fileNameSource the filename of content to sign.
	 * @return the document.
	 * @throws XMLSignerException the failure.
	 */
	public Document signEnveloped(boolean isFileLocation, String fileNameSource) throws XMLSignerException {

		if (!isFileLocation) {
			logger.error(xadesMessagesBundle.getString("error.xml.false.to.file"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.false.to.file"));
		}

		if (fileNameSource == null || fileNameSource.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.file.null", "fileNameSource"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.file.null", "fileNameSource"));
		}
		if (!fileNameSource.substring(fileNameSource.lastIndexOf(".") + 1).equalsIgnoreCase("xml")) {
			logger.error(xadesMessagesBundle.getString("error.xml.not.valid.file"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.not.valid.file"));
		}
		Document varDocToSing = DocumentUtils.loadXMLDocument(fileNameSource);

		return this.signEnveloped(varDocToSing, null);
	}

	/**
	 * Sign a XML file, from String that represents a XML document.
	 *
	 * @param xmlAsString the XML content to sign.
	 * @return the documento.
	 * @throws XMLSignerException the failure
	 */
	public Document signEnveloped(String xmlAsString) throws XMLSignerException {
		if (xmlAsString == null || xmlAsString.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String xmlAsString"));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.parameter.null", "String xmlAsString"));
		}

		return this.signEnveloped(DocumentUtils.loadXMLDocumentFromString(xmlAsString), null);
	}

	/**
	 * Sign a XML file, from XML Document
	 *
	 * @param docToSing the document to sign.
	 * @return the document.
	 * @throws XMLSignerException the failure.
	 */
	public Document signEnveloped(Document docToSing) throws XMLSignerException {
		if (docToSing == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "Document docToSing"));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.parameter.null", "Document docToSing"));
		}

		return this.signEnveloped(docToSing, null);
	}

	/**
	 * Sign a XML file, from byte array that represents a XML document.
	 *
	 * @param content the content to sign.
	 * @return the document.
	 * @throws XMLSignerException the failure.
	 */
	public Document signEnveloped(byte[] content) throws XMLSignerException {

		if (content == null || content.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] content"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] content"));
		}

		return this.signEnveloped(DocumentUtils.loadXMLDocument(content), null);
	}

	/**
	 * Sign a XML file, from InputStream that represents a XML document.
	 *
	 * @param content the content to sign.
	 * @return the document.
	 * @throws XMLSignerException the failure.
	 */
	public Document signEnveloped(InputStream content) throws XMLSignerException {
		if (content == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream  content"));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream  content"));
		}
		return this.signEnveloped(DocumentUtils.loadXMLDocument(content), null);

	}

	/**
	 * Generates a destached XML signature from informed File.
	 *
	 * @param isFile the input stream.
	 * @param fileNameToSign the filename of content to sign.
	 * @return the document.
	 * @throws XMLSignerException the failure.
	 */
	public Document signDetachedEnveloped(InputStream isFile, String fileNameToSign) throws XMLSignerException {

		if (isFile == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isFile"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isFile"));
		}
		if (fileNameToSign == null || fileNameToSign.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String fileNameToSign"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "String fileNameToSign"));
		}
		try {
			byte[] fileContent = IOUtils.toByteArray(isFile);
			return signDetachedEnveloped(fileContent, fileNameToSign);
		} catch (IOException e) {
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		}

	}

	/**
	 * Generates a detached XML signature from a File name and location.
	 *
	 * @param fileNameToSign the filename of content to sign.
	 * @return a Document with signature
	 * @throws XMLSignerException the failure.
	 */
	public Document signDetachedEnveloped(String fileNameToSign) throws XMLSignerException {

		if (fileNameToSign == null || fileNameToSign.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.file.null"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.file.null", "fileNameToSign"));
		}
		try {
			InputStream inputStream = new FileInputStream(fileNameToSign);
			byte[] fileContent = IOUtils.toByteArray(inputStream);
			return signDetachedEnveloped(fileContent, Paths.get(fileNameToSign).getFileName().toString());
		} catch (IOException e) {
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		}

	}

	/**
	 * Generates a destached XML signature from byte array.
	 *
	 * @param content the content.
	 * @param fileNameToSign the filename of document to sign.
	 * @return the document.
	 * @throws XMLSignerException the failure.
	 */
	public Document signDetachedEnveloped(byte[] content, String fileNameToSign) throws XMLSignerException {

		if (content == null || content.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] content"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] content"));
		}
		if (fileNameToSign == null || fileNameToSign.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String fileNameToSign"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "String fileNameToSign"));
		}
		try {
			this.detachedSignaturePack = true;
			detachedFileName = fileNameToSign;
			MessageDigest md = MessageDigest.getInstance(getSignatureDigest());
			byte[] digestValue = md.digest(content);
			return this.signEnveloped(null, digestValue);
		} catch (NoSuchAlgorithmException e) {
			logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
		}

	}

	/**
	 * Generates a destached XML signature from hash byte array.
	 *
	 * @param hash the hash.
	 * @return the documento.
	 * @throws XMLSignerException the failure produced when signing.
	 */
	public Document signDetachedEnveloped(byte[] hash) throws XMLSignerException {

		if (hash == null || hash.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] hash"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] hash"));
		}
		this.detachedSignaturePack = true;
		return this.signEnveloped(null, hash);
	}

	/**
	 * @param docToSing
	 * @param hashToSign
	 * @return
	 * @throws XMLSignerException
	 */
	private Document signEnveloped(Document docToSing, byte[] hashToSign) throws XMLSignerException {

		Init.init();
		Document doc = buildXML(docToSing, hashToSign);

		Document policyDoc;
		policyDoc = PolicyFactory.getInstance().loadXMLPolicy(policy);

		XMLPolicyValidator xMLPolicyValidator = new XMLPolicyValidator(policyDoc);

		if (!xMLPolicyValidator.validate()) {
			logger.error(xadesMessagesBundle.getString("error.policy.not.recognized", policyDoc.getDocumentURI()));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.policy.not.recognized", policyDoc.getDocumentURI()));
		}

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
		
		try {
			new CertificateManager(this.certificate);
		}catch (CertificateValidatorCRLException cvre) {
			logger.warn(cvre.getMessage());
			ConfigurationRepo config = ConfigurationRepo.getInstance();
			config.setOnline(true);
			try {
				new CertificateManager(this.certificate);
			}catch (CertificateValidatorCRLException cvre1) {
				logger.error(cvre1.getMessage());
				throw new CertificateValidatorCRLException(cvre1.getMessage());
			}
		}

		PeriodValidator pV = new PeriodValidator();
		setNotAfterSignerCertificate(pV.valDate(this.certificate));

		int numSignatures = doc.getElementsByTagName("ds:Signature").getLength() - 1;

		Element sigTag = (Element) doc.getElementsByTagName("ds:Signature").item(numSignatures);

		Element objectTag = signedObject(certificate, doc);


		Init.init();
		Canonicalizer c14n = null;
		try {
			c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
		} catch (InvalidCanonicalizerException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}

		byte[] canonicalized = null;

		try {
			canonicalized = c14n.canonicalizeSubtree(objectTag.getElementsByTagName("xades:SignedProperties").item(0));
		} catch (CanonicalizationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}

		Element sigRefTag = createSignatureHashReference(doc, canonicalized);
		doc.getElementsByTagName("ds:SignedInfo").item(numSignatures).appendChild(sigRefTag);

		try {
			c14n = Canonicalizer.getInstance(CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);
		} catch (InvalidCanonicalizerException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}
		byte[] dh;
		try {
			dh = c14n.canonicalizeSubtree(doc.getElementsByTagName("ds:SignedInfo").item(numSignatures));
		} catch (CanonicalizationException e) {
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", e.getMessage()));
		}

		Signature sig;
		try {
			sig = Signature.getInstance(getSignatureAlgorithm());
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
			throw new XMLSignerException(
				xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));

		}

		Element signValueTag = doc.createElementNS(XMLNS, "ds:SignatureValue");
		signValueTag.setAttribute("Id", "value-" + id);
		signValueTag.setIdAttribute("Id", true);
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

		List<String> listMandetedUnsignedProperties = xMLPolicyValidator.getXmlSignaturePolicy().getXmlSignerRules()
			.getMandatedUnsignedQProperties();
		if (listMandetedUnsignedProperties.size() > 0) {

			if (getPrivateKeyToTimestamp() == null) {
				setPrivateKeyToTimestamp(getPrivateKey());
			}
			if (getCertificateChainToTimestamp() == null) {
				setCertificateChainToTimestamp(getCertificateChain());
			}
			Element unsignedProperties = createUnsignedProperties(doc, listMandetedUnsignedProperties);
			objectTag.getElementsByTagName("xades:QualifyingProperties").item(0).appendChild(unsignedProperties);
		}

		sigTag.appendChild(objectTag);

		signedDocument = doc;

		return doc;
	}

	/**
	 * get a Hash Digest for Certificate
	 *
	 * @param cert
	 * @param algorithm
	 * @return
	 * @throws XMLSignerException
	 */
	private String getCertificateDigest(X509Certificate cert, String algorithm) throws XMLSignerException {
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			byte[] digestValue = md.digest(cert.getEncoded());
			return Base64.toBase64String(digestValue);
		} catch (Exception e) {
			logger.error(xadesMessagesBundle.getString("error.cert.digest"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.cert.digest", e.getMessage()));

		}
	}

	/**
	 * Add a Policy information
	 *
	 * @param doc
	 * @return
	 * @throws XMLSignerException
	 */
	private Element addPolicy(Document doc) throws XMLSignerException {

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
		sigDigestMethod.setAttribute("Algorithm", AlgorithmsValues.getSignatureDigest(getSignatureDigest()));
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

	/**
	 * Create the SignedObject
	 *
	 * @param cert
	 * @param doc
	 * @return
	 */
	private Element signedObject(X509Certificate cert, Document doc) {

		Element sigObject = doc.createElementNS(XMLNS, "ds:Object");

		Element sigQualify = doc.createElementNS(XAdESv1_3_2, "xades:QualifyingProperties");
		sigQualify.setAttribute("xmlns:xades", "http://uri.etsi.org/01903/v1.3.2#");
		sigQualify.setAttribute("Target", "#" + id);
		sigObject.appendChild(sigQualify);

		Element sigProp = doc.createElementNS(XAdESv1_3_2, "xades:SignedProperties");
		sigProp.setAttribute("Id", "xades-" + id);
		sigProp.setIdAttribute("Id", true);
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
		//sigDigMet.setAttribute("Algorithm", "http://www.w3.org/2000/09/xmldsig#sha256");
		sigCertDig.appendChild(sigDigMet);

		Element sigDigValue = doc.createElementNS(XMLNS, "ds:DigestValue");
		sigDigValue.setTextContent(getCertificateDigest(cert, "SHA1"));
		//sigDigValue.setTextContent(getCertificateDigest(cert, "SHA-256"));
		sigCertDig.appendChild(sigDigValue);

		Element sigIssuerSerial = doc.createElementNS(XAdESv1_3_2, "xades:IssuerSerial");
		sigCert.appendChild(sigIssuerSerial);

		String issuerName = cert.getIssuerX500Principal().toString();
		String serialId = cert.getSerialNumber().toString();

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
		sigDataObjFormat.setAttribute("ObjectReference", "#r" + id);
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

	/**
	 * create the SignatureHashReference tag
	 *
	 * @param doc
	 * @param signedTagData
	 * @return
	 * @throws XMLSignerException
	 */
	private Element createSignatureHashReference(Document doc, byte[] signedTagData) throws XMLSignerException {

		HashMap<String, String> param = new HashMap<String, String>();
		param.put("id", "sigref" + id);
		param.put("type", Constants.SignedProperties);
		param.put("uri", "#xades-" + id);
		param.put("alg", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
		param.put("digAlg", AlgorithmsValues.getSignatureDigest(getSignatureDigest()));

		MessageDigest md = null;

		try {
			md = MessageDigest.getInstance(getSignatureDigest());
		} catch (NoSuchAlgorithmException e) {
			logger.error(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.no.algorithm", e.getMessage()));
		}

		byte[] digestValue = md.digest(signedTagData);
		param.put("digVal", Base64.toBase64String(digestValue));

		return createReferenceTag(doc, param);
	}

	/**
	 * create a Reference Tag
	 *
	 * @param doc
	 * @param params
	 * @return
	 */
	private Element createReferenceTag(Document doc, HashMap<String, String> params) {

		Element referenceTag = doc.createElementNS(XMLNS, "ds:Reference");
		if (params.containsKey("id")) {
			referenceTag.setAttribute("Id", params.get("id"));
			referenceTag.setIdAttribute("Id", true);
		}
		if (params.containsKey("type")) referenceTag.setAttribute("Type", params.get("type"));
		if (params.containsKey("uri")) referenceTag.setAttribute("URI", params.get("uri"));
		// sigInfTag.appendChild(referenceTag );

		if (!params.containsKey("no_transforms")) {
			Element transformsTag = doc.createElementNS(XMLNS, "ds:Transforms");
			referenceTag.appendChild(transformsTag);

			if (params.containsKey("transAlg1")) {
				Element transAlg = doc.createElementNS(XMLNS, "ds:Transform");
				transAlg.setAttribute("Algorithm", params.get("transAlg1"));
				transformsTag.appendChild(transAlg);
			}

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

			if (params.containsKey("transAlg2")) {
				Element transAlg = doc.createElementNS(XMLNS, "ds:Transform");
				transAlg.setAttribute("Algorithm", params.get("transAlg2"));
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

	/**
	 * Create a XML signature tag or file
	 *
	 * @param docToSign          XMLDocument to Sign
	 * @param detachedHashToSign a calculated Hash to Sign on detachedPack
	 * @return
	 * @throws XMLSignerException
	 */
	private Document buildXML(Document docToSign, byte[] detachedHashToSign) throws XMLSignerException {

		Document bodyDoc = null;

		if (detachedSignaturePack) {
			try {
				bodyDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			} catch (ParserConfigurationException e) {
				logger.error(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
				throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parser", e.getMessage()));
			}
		} else {
			bodyDoc = docToSign;
		}

		Element signatureTag = bodyDoc.createElementNS(XMLNS, "ds:Signature");
		signatureTag.setAttributeNS("http://www.w3.org/2000/xmlns/", XMLNS_DS, XMLNS);
		signatureTag.setAttributeNS("http://www.w3.org/2000/xmlns/", XMLNS_XADES, XAdESv1_3_2);
		signatureTag.setAttribute("Id", id);
		signatureTag.setIdAttribute("Id", true);

		Element sigInfTag = bodyDoc.createElementNS(XMLNS, "ds:SignedInfo");
		signatureTag.appendChild(sigInfTag);

		Element canonicalizationMethodTag = bodyDoc.createElementNS(XMLNS, "ds:CanonicalizationMethod");
		//canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

		sigInfTag.appendChild(canonicalizationMethodTag);

		Element signatureMethodTag = bodyDoc.createElementNS(XMLNS, "ds:SignatureMethod");
		signatureMethodTag.setAttribute("Algorithm", AlgorithmsValues.getSignatureAlgorithm(getSignatureAlgorithm()));
		sigInfTag.appendChild(signatureMethodTag);

		HashMap<String, String> param = new HashMap<String, String>();
		//param.put("type", "");
		param.put("uri", "");
		param.put("id", "r-" + id);
		param.put("text", "not(ancestor-or-self::ds:Signature)");
		param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
		param.put("digAlg", AlgorithmsValues.getSignatureDigest(getSignatureDigest()));

		if (detachedSignaturePack) {
			param.put("no_transforms", "true");
			//param.put("type", "");
			param.put("uri", detachedFileName);
			param.put("digVal", Base64.toBase64String(detachedHashToSign));
			Element referenceTag = createReferenceTag(bodyDoc, param);
			sigInfTag.appendChild(referenceTag);
			bodyDoc.appendChild(signatureTag);

		} else {
			Element docData = DocumentUtils.getDocumentData(bodyDoc);
			byte[] docHash = DocumentUtils.getShaCanonizedValue(getSignatureDigest(), docData,
				"http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
			//param.put("type", "");
			param.put("uri", "");
			param.put("id", "r" + id);
			param.put("text", "not(ancestor-or-self::ds:Signature)");
			param.put("alg", "http://www.w3.org/TR/1999/REC-xpath-19991116");
			param.put("digAlg", AlgorithmsValues.getSignatureDigest(getSignatureDigest()));
			param.put("transAlg1", "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
			param.put("transAlg2", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
			param.put("digVal", Base64.toBase64String(docHash));
			docHash = new byte[0];
			Element referenceTag = createReferenceTag(bodyDoc, param);
			sigInfTag.appendChild(referenceTag);
			bodyDoc.getDocumentElement().appendChild(signatureTag);
		}

		return bodyDoc;
	}

	/**
	 * create the UnsignedProperties acording to Policy
	 *
	 * @param doc
	 * @param parmProperties
	 * @return
	 * @throws XMLSignerException
	 */
	private Element createUnsignedProperties(Document doc, List<String> parmProperties) throws XMLSignerException {

		Element unsignedProperties = doc.createElementNS(XAdESv1_3_2, "xades:UnsignedProperties");
		Element unsignedSignatureProperties = doc.createElementNS(XAdESv1_3_2, "xades:UnsignedSignatureProperties");
		unsignedProperties.appendChild(unsignedSignatureProperties);
		for (String propertie : parmProperties) {
			Element unsignedSignaturePropertie = null;
			switch (propertie) {
				case "SignatureTimeStamp":
					unsignedSignaturePropertie = createSignatureTimeStampProperty(doc);
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
					// break;
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

	/**
	 * create the SignatureTimeStamp Property tag
	 *
	 * @param doc
	 * @return
	 */
	private Element createSignatureTimeStampProperty(Document doc) {

		Element signatureTimeStamp = doc.createElement("xades:SignatureTimeStamp");
		Element canonicalizationMethodTag = doc.createElementNS(XMLNS, "ds:CanonicalizationMethod");
		canonicalizationMethodTag.setAttribute("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments");
		signatureTimeStamp.appendChild(canonicalizationMethodTag);
		Element encapsulatedTimeStamp = doc.createElement("xades:EncapsulatedTimeStamp");
		encapsulatedTimeStamp.setAttribute("Id", "TimeStamp" + id);
		XMLTimeStampToken varXMLTimeStampToken = new XMLTimeStampToken(getPrivateKeyToTimestamp(),
			getCertificateChainToTimestamp(), docSignature, null);
		String timeStampContent = Base64.toBase64String(varXMLTimeStampToken.getTimeStampToken());
		encapsulatedTimeStamp.setTextContent(timeStampContent);
		signatureTimeStamp.appendChild(encapsulatedTimeStamp);
		return signatureTimeStamp;
	}

	public void saveSignedDocument(String fileName) throws TransformerException, FileNotFoundException {
		OutputStream os = new FileOutputStream(fileName);
		TransformerFactory tf = TransformerFactory.newInstance();
		Transformer trans = tf.newTransformer();
		trans.transform(new DOMSource(signedDocument), new StreamResult(os));
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
