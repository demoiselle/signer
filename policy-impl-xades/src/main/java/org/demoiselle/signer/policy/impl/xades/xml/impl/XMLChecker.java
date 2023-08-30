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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.apache.commons.io.IOUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateCoreException;
import org.demoiselle.signer.core.exception.CertificateRevocationException;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.CRLValidator;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.xml.icpb.XMLPolicyValidator;
import org.demoiselle.signer.policy.engine.xml.icpb.XMLSignaturePolicy;
import org.demoiselle.signer.policy.engine.xml.icpb.XMLSignerAlgConstraint;
import org.demoiselle.signer.policy.impl.xades.XMLSignatureInformations;
import org.demoiselle.signer.policy.impl.xades.XMLSignerException;
import org.demoiselle.signer.policy.impl.xades.util.DocumentUtils;
import org.demoiselle.signer.policy.impl.xades.util.PolicyUtils;
import org.demoiselle.signer.policy.impl.xades.xml.Checker;
import org.demoiselle.signer.timestamp.Timestamp;
import org.demoiselle.signer.timestamp.connector.TimeStampOperator;
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
public class XMLChecker implements Checker {

	private static final Logger logger = LoggerFactory.getLogger(XMLChecker.class);
	private boolean isDetached = false;
	private List<XMLSignatureInformations> signaturesInfo = new ArrayList<XMLSignatureInformations>();
	private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";
	private Timestamp varTimestampToSignature = null;
	private LinkedList<String> validationErrors = new LinkedList<String>();
	private LinkedList<String> validationWaring = new LinkedList<String>();

	/**
	 * Verify signature from File Name and location. (example:
	 * check(true,"/tmp/file.xml");
	 *
	 * @param isFileLocation true if the next parameter is a path and name for XML
	 *                       file
	 * @param xmlSignedFile  path and name for XML file
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(boolean isFileLocation, String xmlSignedFile) throws XMLSignerException, NoSuchProviderException {

		if (!isFileLocation) {
			logger.error(xadesMessagesBundle.getString("error.xml.false.to.file"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.false.to.file"));
		}

		if (xmlSignedFile == null || xmlSignedFile.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.file.null", "xmlSignedFile"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.file.null", "xmlSignedFile"));
		}
		if (!xmlSignedFile.substring(xmlSignedFile.lastIndexOf(".") + 1).equalsIgnoreCase("xml")) {
			logger.error(xadesMessagesBundle.getString("error.xml.not.valid.file"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.not.valid.file"));
		}

		Document doc = DocumentUtils.loadXMLDocument(xmlSignedFile);
		return verify(doc);
	}

	/**
	 * * XML signature validation using byte[] data. The content must contains both
	 * content and signature
	 *
	 * @param docData fake.
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(byte[] docData) throws XMLSignerException, NoSuchProviderException {
		if (docData == null || docData.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] docData"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] docData"));
		}
		Document doc = DocumentUtils.loadXMLDocument(docData);
		return verify(doc);
	}

	/**
	 * XML signature validation using document. The file must contains both content
	 * and signature
	 *
	 * @param doc document
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(Document doc) throws XMLSignerException, NoSuchProviderException {
		if (doc == null || doc.getChildNodes().getLength() <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "Document doc"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "Document doc"));
		}
		return verify(doc);
	}

	/**
	 * XML signature validation with detached content from path and file names
	 * example: check("/tmp/signedFile","/tmp/signaturefile.xml")
	 *
	 * @param signedContentFileName fake.
	 * @param signatureFileName     fake.
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(String signedContentFileName, String signatureFileName) throws XMLSignerException, NoSuchProviderException {

		if (signedContentFileName == null || signedContentFileName.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String signedContentFileName"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "String signedContentFileName"));
		}
		if (signatureFileName == null || signatureFileName.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String signatureFileName"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "String signatureFileName"));
		}
		if (!signatureFileName.substring(signatureFileName.lastIndexOf(".") + 1).equalsIgnoreCase("xml")) {
			logger.error(xadesMessagesBundle.getString("error.xml.not.valid.file"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.not.valid.file"));
		}

		return check(DocumentUtils.readContent(signedContentFileName),
				DocumentUtils.loadXMLDocument(signatureFileName));
	}

	/**
	 * XML signature validation with detached content .
	 *
	 * @param signedContent a signed content in byte[] format
	 * @param signature     the XML signature in byte[] format
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(byte[] signedContent, byte[] signature) throws XMLSignerException, NoSuchProviderException {

		if (signedContent == null || signedContent.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] signedContent"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] signedContent"));
		}
		if (signature == null || signature.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] signature"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] signature"));
		}
		return check(signedContent, DocumentUtils.loadXMLDocument(signature));
	}

	/**
	 * XML signature validation from InputStream that represents a XML file.
	 *
	 * @param isXMLFile fake.
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(InputStream isXMLFile) throws XMLSignerException, NoSuchProviderException {
		if (isXMLFile == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isXMLFile"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isXMLFile"));
		}
		return check(DocumentUtils.loadXMLDocument(isXMLFile));
	}

	/**
	 * XML signature detached validation from InputStream that represents a content
	 * and XML Signature
	 *
	 * @param isContent      fake.
	 * @param isXMLSignature fake.
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	@Override
	public boolean check(InputStream isContent, InputStream isXMLSignature) throws XMLSignerException, NoSuchProviderException {
		if (isContent == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
		}
		if (isXMLSignature == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isXMLSignature"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isXMLSignature"));
		}
		try {
			return check(IOUtils.toByteArray(isContent), DocumentUtils.loadXMLDocument(isXMLSignature));
		} catch (IOException e) {
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		}
	}

	@Override
	public boolean checkHash(byte[] contentHash, String xmlSignature) throws XMLSignerException, NoSuchProviderException {

		if (contentHash == null || contentHash.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] contentHash"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] contentHash"));
		}
		if (xmlSignature == null || xmlSignature.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String xmlSignature"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "String xmlSignature"));
		}
		return checkHash(contentHash, DocumentUtils.loadXMLDocument(xmlSignature));
	}

	@Override
	public boolean checkHash(InputStream isContent, Document xmlSignature) throws XMLSignerException, NoSuchProviderException {

		if (isContent == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
		}
		if (xmlSignature == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "Document xmlSignature"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "Document xmlSignature"));
		}
		try {
			return checkHash(IOUtils.toByteArray(isContent), xmlSignature);
		} catch (IOException e) {
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		}

	}

	@Override
	public boolean checkHash(InputStream isContent, InputStream isXMLSignature) throws XMLSignerException, NoSuchProviderException {
		if (isContent == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
		}
		if (isXMLSignature == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isXMLSignature"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isXMLSignature"));
		}
		try {
			return checkHash(IOUtils.toByteArray(isContent), DocumentUtils.loadXMLDocument(isXMLSignature));
		} catch (IOException e) {
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		}
	}

	@Override
	public boolean checkHash(InputStream isContent, String xmlSignature) throws XMLSignerException, NoSuchProviderException {
		if (isContent == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "InputStream isContent"));
		}
		if (xmlSignature == null) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "String  xmlSignature"));
			throw new XMLSignerException(
					xadesMessagesBundle.getString("error.xml.parameter.null", "String  xmlSignature"));
		}
		try {
			return checkHash(IOUtils.toByteArray(isContent), DocumentUtils.loadXMLDocument(xmlSignature));
		} catch (IOException e) {
			logger.error(xadesMessagesBundle.getString("error.io", e.getMessage()));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.io", e.getMessage()));
		}
	}

	/**
	 * XML signature validation with detached hash content and signature.
	 *
	 * @param docHash   fake.
	 * @param signature fake.
	 * @return fake.
	 * @throws XMLSignerException 
	 * @throws NoSuchProviderException 
	 */
	public boolean checkHash(byte[] docHash, byte[] signature) throws NoSuchProviderException, XMLSignerException {
		if (docHash == null || docHash.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] docHash"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] docHash"));
		}
		if (signature == null || signature.length <= 0) {
			logger.error(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] signature"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.parameter.null", "byte[] signature"));
		}
		return checkHash(docHash, DocumentUtils.loadXMLDocument(signature));

	}

	/**
	 * Verify signature from String that represents a XML Document The content must
	 * contains both content and signature
	 *
	 * @param xmlAsString fake.
	 * @return fake.
	 * @throws NoSuchProviderException 
	 */
	public boolean check(String xmlAsString) throws NoSuchProviderException {

		if (xmlAsString == null || xmlAsString.isEmpty()) {
			logger.error(xadesMessagesBundle.getString("error.xml.string.file.null", "String xmlAsString"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.xml.file.null", "String xmlAsString"));
		}

		Document doc = DocumentUtils.loadXMLDocumentFromString(xmlAsString);
		return verify(doc);
	}

	/**
	 * Check detached Signature with signed data content
	 *
	 * @param docData
	 * @param signature
	 * @return
	 * @throws NoSuchProviderException 
	 */
	private boolean check(byte[] docData, Document signature) throws NoSuchProviderException {
		isDetached = true;
		boolean signatureOk = true;
		verify(signature);

		try {

			Element signatureInfoTag = getSignatureElement("SignedInfo", (Element) signature.getChildNodes().item(0),
					true);
			NodeList references = signatureInfoTag.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
			for (int i = 0; i < references.getLength(); i++) {
				if (((Element) references.item(i)).getAttribute("Type").isEmpty()) {
					Element digestMethod = getSignatureElement("DigestMethod", ((Element) references.item(i)), true);
					Element digestValue = getSignatureElement("DigestValue", ((Element) references.item(i)), true);
					String strAlg = AlgorithmsValues.getDigestOnSignature(digestMethod.getAttribute("Algorithm"));
					String value = digestValue.getTextContent();

					if (!strAlg.isEmpty()) {
						MessageDigest messageDigest = MessageDigest.getInstance(strAlg);
						String hashValue = Base64.toBase64String(messageDigest.digest(docData));

						if (!value.equals(hashValue)) {
							validationErrors.add(xadesMessagesBundle.getString("error.xml.hash.invalid"));
							logger.error(xadesMessagesBundle.getString("error.xml.hash.invalid"));
							signatureOk = false;
						}
					} else {
						logger.error(xadesMessagesBundle.getString("error.xml. hash.not.found"));
						validationErrors.add(xadesMessagesBundle.getString("error.xml. hash.not.found"));
					}
				}
			}
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml. hash.not.found"));
			logger.error(xadesMessagesBundle.getString("error.xml. hash.not.found"));
			return false;
		}
		return signatureOk;
	}

	/**
	 * Check detached Signature with signed hash from signed data.
	 *
	 * @param docHash   the hahs.
	 * @param signature the document.
	 * @return {@code true} if checked ok.
	 * @throws NoSuchProviderException 
	 */
	public boolean checkHash(byte[] docHash, Document signature) throws NoSuchProviderException {
		isDetached = true;
		boolean signatureOk = true;
		verify(signature);
		Element signatureInfoTag = getSignatureElement("SignedInfo", (Element) signature.getChildNodes().item(0), true);
		NodeList references = signatureInfoTag.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
		for (int i = 0; i < references.getLength(); i++) {
			if (((Element) references.item(i)).getAttribute("Type").isEmpty()) {
				Element digestValue = getSignatureElement("DigestValue", ((Element) references.item(i)), true);
				String value = digestValue.getTextContent();
				String hashValue = Base64.toBase64String(docHash);
				if (!value.equals(hashValue)) {
					validationErrors.add(xadesMessagesBundle.getString("error.xml.hash.invalid"));
					logger.error(xadesMessagesBundle.getString("error.xml.hash.invalid"));
				}
			}
		}
		return signatureOk;
	}

	private Element getSignatureElement(String tagName, Element parent, boolean mandatory) {
		try {
			NodeList value = parent.getElementsByTagNameNS(XMLSignature.XMLNS, tagName);
			if (value.getLength() == 0) {
				if (mandatory) {
					validationErrors.add(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
					logger.error(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
				} else {
					validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
					logger.warn(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
				}

			}
			return (Element) value.item(0);
		} catch (Exception e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
			logger.error(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
			return null;
		}

	}

	private Element getXadesElement(String tagName, Element parent, boolean mandatory) {
		if (parent == null) {
			validationWaring.add(xadesMessagesBundle.getString("error.xml.parent.element.not.found", tagName));
			logger.warn(xadesMessagesBundle.getString("error.xml.parent.element.not.found", tagName));
			return null;
		}
		if (tagName == null) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.invalid.name", parent.getTagName()));
			logger.error(xadesMessagesBundle.getString("error.xml.invalid.name", parent.getTagName()));
			return null;
		}
		NodeList value = parent.getElementsByTagNameNS(XAdESv1_3_2, tagName);
		if (value.getLength() == 0) {
			if (mandatory) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
				logger.error(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
			} else {
				validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
				logger.warn(xadesMessagesBundle.getString("error.xml.element.not.found", tagName));
			}

			return null;
		}
		return (Element) value.item(0);
	}

	private String getAttribute(Element node, String attr, boolean mandatory) {
		String attribute = node.getAttribute(attr);
		if (attr.isEmpty()) {
			if (mandatory) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.element.not.found", attr));
				logger.error(xadesMessagesBundle.getString("error.xml.element.not.found", attr));
			} else {
				validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found", attr));
				logger.warn(xadesMessagesBundle.getString("error.xml.element.not.found", attr));
			}

		}
		return attribute;
	}

	private boolean verifyDigest(Element signatureTag, String digestMethod, String digestValue,
			String canonicalString) {

		Init.init();
		Element objectTag = (Element) signatureTag.getElementsByTagNameNS(XMLSignature.XMLNS, "Object").item(0);
		byte[] canonicalized = null;
		Canonicalizer c14n;
		try {
			c14n = Canonicalizer.getInstance(canonicalString);
			canonicalized = c14n.canonicalizeSubtree(objectTag.getElementsByTagName("xades:SignedProperties").item(0));
		} catch (InvalidCanonicalizerException | CanonicalizationException e1) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.hash.data.invalid", digestMethod));
			logger.error(xadesMessagesBundle.getString("error.xml.hash.data.invalid", digestMethod));
			return false;
		}
		MessageDigest md = null;

		try {
			String algorithm = AlgorithmsValues.getDigestOnSignature(digestMethod);
			if (algorithm != null) {
				md = MessageDigest.getInstance(algorithm);
				byte[] signatureDigestValue = md.digest(canonicalized);
				if (!Base64.toBase64String(signatureDigestValue).equals(digestValue)) {
					validationErrors.add(xadesMessagesBundle.getString("error.xml.hash.invalid"));
					logger.error(xadesMessagesBundle.getString("error.xml.hash.invalid"));
					return false;
				}
			} else {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.invalid.digest.method", digestMethod));
				logger.error(xadesMessagesBundle.getString("error.xml.invalid.digest.method", digestMethod));
				return false;
			}
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.invalid.digest.method", digestMethod));
			logger.error(xadesMessagesBundle.getString("error.xml.invalid.digest.method", digestMethod));
			return false;
		}
		return true;
	}

	private boolean verifyXPath(Document doc, String digestMethod, String digestValue, NodeList transformsTags) {

		String xPathTransformAlgorithm = "";

		for (int i = 0; i < transformsTags.getLength(); i++) {
			NodeList transformTag = ((Element) transformsTags.item(i)).getElementsByTagNameNS(XMLSignature.XMLNS,
					"Transform");
			for (int j = 0; j < transformTag.getLength(); j++) {
				if (AlgorithmsValues.isCanonicalMethods(((Element) transformTag.item(j)).getAttribute("Algorithm"))) {
					xPathTransformAlgorithm = ((Element) transformTag.item(j)).getAttribute("Algorithm");
					break;
				}
			}
		}

		if (xPathTransformAlgorithm.isEmpty()) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", digestMethod));
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.Canonicalizer", digestMethod));
		}

		try {
			Element docData = DocumentUtils.getDocumentData(doc);
			byte[] docHash = DocumentUtils.getShaCanonizedValue(AlgorithmsValues.getDigestOnSignature(digestMethod),
					docData, xPathTransformAlgorithm);
			if (!Base64.toBase64String(docHash).equals(digestValue)) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.digest.invalid"));
				logger.error(xadesMessagesBundle.getString("error.xml.digest.invalid"));
				return false;
			}
		} catch (Exception e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.digest.invalid"));
			logger.error(xadesMessagesBundle.getString("error.xml.digest.invalid"));
			return false;
		}

		return true;
	}

	private X509Certificate getCertificate(String x509Certificate) throws CertificateException, NoSuchProviderException {
		byte encodedCert[] = Base64.decode(x509Certificate);
		ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
		return (X509Certificate) certFactory.generateCertificate(inputStream);
	}

	private boolean verifyHash(Element signatureTag, Element signatureInfoTag, String signatureValue,
			X509Certificate cert) {
		try {
			Element canonicalizationMethodTag = (Element) signatureTag
					.getElementsByTagNameNS(XMLSignature.XMLNS, "CanonicalizationMethod").item(0);
			Element signatureMethod = (Element) signatureTag
					.getElementsByTagNameNS(XMLSignature.XMLNS, "SignatureMethod").item(0);

			Init.init();
			Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethodTag.getAttribute("Algorithm"));

			byte[] dh = c14n.canonicalizeSubtree(signatureInfoTag);

			String aos = AlgorithmsValues.getAlgorithmsOnSignature(signatureMethod.getAttribute("Algorithm"));
			Signature verify = Signature.getInstance(aos);
			verify.initVerify(cert);
			verify.update(dh);
			if (!verify.verify(Base64.decode(signatureValue))) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.signature.invalid"));
				logger.error(xadesMessagesBundle.getString("error.xml.signature.invalid"));
			} else {
				return true;
			}

		} catch (InvalidCanonicalizerException | CanonicalizationException | InvalidKeyException | DOMException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.signature.invalid"));
			logger.error(xadesMessagesBundle.getString("error.xml.signature.invalid"));
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.nosuch.algorithm.exception"));
			logger.error(xadesMessagesBundle.getString("error.xml.nosuch.algorithm.exception"));
		} catch (SignatureException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));
			logger.error(xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));
		}

		return false;

	}

	private void verifyCertificate(X509Certificate varCert) {
		CRLValidator cV = new CRLValidator();
		try {
			cV.validate(varCert);
		} catch (CertificateValidatorCRLException cvce) {
			validationErrors.add(cvce.getMessage());
			logger.error(cvce.getMessage());
		} catch (CertificateRevocationException cre) {
			validationErrors.add(xadesMessagesBundle.getString("error.certificate.repealed", cre.getMessage()));
			logger.error("certificado revogado");
		}

		PeriodValidator pV = new PeriodValidator();
		try {
			pV.valDate(varCert);
		} catch (CertificateValidatorException cve) {
			validationWaring.add(cve.getMessage());
			logger.warn(cve.getMessage());
		}

	}

	private XMLSignaturePolicy verifyPolicy(Element signature, String policyOID, String signatureMethod,
			String signatureValue) {
		boolean isValidAlgorithm = false;
		if (policyOID == null) {
			validationWaring.add(xadesMessagesBundle.getString("error.xml.policy.null"));
			logger.warn(xadesMessagesBundle.getString("error.xml.policy.null"));
		}
		if (policyOID.contains("urn:oid:")) {
			policyOID = policyOID.substring(policyOID.lastIndexOf(":") + 1, policyOID.length());
		}
		/*
		 * else { validationErrors.add(xadesMessagesBundle.getString(
		 * "error.policy.not.recognized", policyOID));
		 * logger.error(xadesMessagesBundle.getString("error.policy.not.recognized",
		 * policyOID)); return null; }
		 */

		Document policyDoc = PolicyFactory.getInstance().loadXMLPolicy(PolicyUtils.getPolicyByOid(policyOID));

		XMLPolicyValidator xmlPolicyValidator = new XMLPolicyValidator(policyDoc);

		if (!xmlPolicyValidator.validate()) {
			logger.warn(xadesMessagesBundle.getString("error.policy.not.recognized", policyOID));
			validationWaring.add(xadesMessagesBundle.getString("error.policy.not.recognized", policyOID));
		}

		List<XMLSignerAlgConstraint> listSignerAlgConstraint = xmlPolicyValidator.getXmlSignaturePolicy()
				.getXmlSignerAlgConstraintList();

		for (XMLSignerAlgConstraint xmlSignerAlgConstraint : listSignerAlgConstraint)
			if (xmlSignerAlgConstraint.getAlgId().equals(signatureMethod)) {
				if (xmlSignerAlgConstraint.getMinKeyLength() != null) {
					if ((8 * Base64.decode(signatureValue).length) >= Integer
							.parseInt(xmlSignerAlgConstraint.getMinKeyLength())) {
						isValidAlgorithm = true;
					} else {
						validationErrors.add(xadesMessagesBundle.getString("error.xml.size.not.allowed"));
						logger.error(xadesMessagesBundle.getString("error.xml.size.not.allowed"));
					}
				}
				break;
			}

		if (!isValidAlgorithm) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.invalid.algorithm", policyOID));
			logger.error(xadesMessagesBundle.getString("error.xml.invalid.algorithm", policyOID));
		}
		return xmlPolicyValidator.getXmlSignaturePolicy();
	}

	private void verifySignature(Element signature, X509Certificate cert) {

		try {

			Init.init();
			Element canonicalizationMethodTag = getSignatureElement("CanonicalizationMethod", signature, true);
			Element signatureMethodTag = getSignatureElement("SignatureMethod", signature, true);
			Element signatureValueTag = getSignatureElement("SignatureValue", signature, true);
			String canonicalizationMethod = getAttribute(canonicalizationMethodTag, "Algorithm", true);
			String signatureMethod = AlgorithmsValues
					.getAlgorithmsOnSignature(getAttribute(signatureMethodTag, "Algorithm", true));

			Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);

			byte[] dh = c14n.canonicalizeSubtree(signature.getElementsByTagName("ds:SignedInfo").item(0));
			byte[] sigValue = Base64.decode(signatureValueTag.getTextContent());

			if (!AlgorithmsValues.isCanonicalMethods(canonicalizationMethod)) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.canonicalizer.not.allowed"));
				logger.error(xadesMessagesBundle.getString("error.xml.canonicalizer.not.allowed"));
			}

			Signature sig = Signature.getInstance(signatureMethod);
			sig.initVerify(cert);
			sig.update(dh);
			if (!sig.verify(sigValue)) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.signature.hash"));
				logger.error(xadesMessagesBundle.getString("error.xml.signature.hash"));
			}

		} catch (InvalidCanonicalizerException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.Invalid.canonicalizer", e.getMessage()));
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.canonicalizer", e.getMessage()));
		} catch (CanonicalizationException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.Invalid.canonicalizer", e.getMessage()));
			logger.error(xadesMessagesBundle.getString("error.xml.Invalid.canonicalizer", e.getMessage()));
		} catch (NoSuchAlgorithmException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.nosuch.algorithm.exception"));
			logger.error(xadesMessagesBundle.getString("error.xml.nosuch.algorithm.exception"));
		} catch (InvalidKeyException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.invalid.key.exception"));
			logger.error(xadesMessagesBundle.getString("error.xml.invalid.key.exception"));
		} catch (SignatureException e) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));
			logger.error(xadesMessagesBundle.getString("error.xml.signature.exception", e.getMessage()));
		}
	}

	private boolean verify(Document doc) throws NoSuchProviderException {

		Init.init();
		boolean signatureOK = false;
		NodeList root = doc.getChildNodes();
		NodeList signatureListTags = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

		if (root.item(0) == signatureListTags.item(0)) {
			if (!isDetached) {
				validationErrors.add(xadesMessagesBundle.getString("error.xml.detached.content"));
				logger.error(xadesMessagesBundle.getString("error.xml.detached.content"));
				XMLSignatureInformations sigInf = new XMLSignatureInformations();
				sigInf.setValidatorErrors(validationErrors);
				signaturesInfo.add(sigInf);
				return signatureOK;
			}
		}

		int sizeSigList = signatureListTags.getLength();

		if (sizeSigList < 1) {
			validationErrors.add(xadesMessagesBundle.getString("error.xml.signature.not.found"));
			logger.error(xadesMessagesBundle.getString("error.xml.signature.not.found"));
			XMLSignatureInformations sigInf = new XMLSignatureInformations();
			sigInf.setValidatorErrors(validationErrors);
			signaturesInfo.add(sigInf);
			return signatureOK;
		} else {
			for (int i = 0; i < sizeSigList; i++) {

				XMLSignatureInformations sigInf = new XMLSignatureInformations();

				Element sigPolicyId = null;
				Element signatureTag = (Element) signatureListTags.item(i);
				Element keyInfoTag = getSignatureElement("KeyInfo", signatureTag, true);
				Element X509DataTag = getSignatureElement("X509Data", keyInfoTag, true);
				Element X509CertificateTag = getSignatureElement("X509Certificate", X509DataTag, true);
				String x509Certificate = X509CertificateTag.getTextContent();
				X509Certificate cert = null;
				try {
					cert = getCertificate(x509Certificate);
				} catch (CertificateException e) {
					signatureOK = false;
					validationErrors.add(xadesMessagesBundle.getString("error.invalid.certificate"));
				}
				if (cert != null) {
					verifyCertificate(cert);
					LinkedList<X509Certificate> varChain = (LinkedList<X509Certificate>) CAManager.getInstance()
							.getCertificateChain(cert);
					sigInf.setIcpBrasilcertificate(new BasicCertificate(cert));
					sigInf.setChain(varChain);
					sigInf.setNotAfter(cert.getNotAfter());
				}
				Element objectTag = getSignatureElement("Object", signatureTag, false);
				if (objectTag != null) {
					Element qualifyingPropertiesTag = getXadesElement("QualifyingProperties", objectTag, true);

					Element signaturePolicyIdentifier = getXadesElement("SignaturePolicyIdentifier",
							qualifyingPropertiesTag, false);

					sigPolicyId = getXadesElement("SigPolicyId", signaturePolicyIdentifier, false);

					NodeList referenceTag = signatureTag.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");

					for (int j = 0; j < referenceTag.getLength(); j++) {
						signatureOK = true;
						Element actualReferenceTag = (Element) referenceTag.item(j);
						NodeList transformsTags = actualReferenceTag.getElementsByTagNameNS(XMLSignature.XMLNS,
								"Transforms");

						Element digestMethodTag = getSignatureElement("DigestMethod", (Element) referenceTag.item(j),
								true);
						String digestMethod = getAttribute(digestMethodTag, "Algorithm", true);
						Element digestValueTag = getSignatureElement("DigestValue", (Element) referenceTag.item(j),
								true);
						String digestValue = digestValueTag.getTextContent();

						if (actualReferenceTag.getElementsByTagNameNS(XMLSignature.XMLNS, "XPath").getLength() > 0) {
							if (!verifyXPath(doc, digestMethod, digestValue, transformsTags)) {
								validationErrors.add(xadesMessagesBundle.getString("error.xml.document.fail"));
								signatureOK = false;
							}
						} else if (((Element) referenceTag.item(j)).hasAttribute("Type")) {
							if (((Element) referenceTag.item(j)).getAttribute("Type").endsWith("#SignedProperties")) {
								Element transformTag = (Element) ((Element) referenceTag.item(j))
										.getElementsByTagNameNS(XMLSignature.XMLNS, "Transform").item(0);
								String canonString = transformTag.getAttribute("Algorithm");
								if (!verifyDigest((Element) signatureListTags.item(i), digestMethod, digestValue,
										canonString)) {
									validationErrors.add(xadesMessagesBundle.getString("error.xml.digest.invalid"));
									signatureOK = false;
								}
							}
						}
					}

					Element signedPropertiesTag = getXadesElement("SignedProperties", qualifyingPropertiesTag, true);
					Element signedSignaturePropertiesTag = getXadesElement("SignedSignatureProperties",
							signedPropertiesTag, true);
					Element signedTime = getXadesElement("SigningTime", signedSignaturePropertiesTag, true);
					if (signedTime == null) {
						validationWaring.add(xadesMessagesBundle.getString("error.xml.signing.time.not.found"));
					} else {
						DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
						try {
							sigInf.setSignDate(formatter.parse(signedTime.getTextContent()));
						} catch (DOMException | ParseException e) {
							validationWaring.add(xadesMessagesBundle.getString("error.date.parser", e.getMessage()));
						}
					}

					Element signingCertificateTag = getXadesElement("SigningCertificate", signedSignaturePropertiesTag,
							true);
					if (signingCertificateTag == null) {
						signingCertificateTag = getXadesElement("SigningCertificateV2", signedSignaturePropertiesTag,
								true);
					}
					Element certTag = getXadesElement("Cert", signingCertificateTag, true);
					Element certDigestTag = getXadesElement("CertDigest", certTag, true);

					if (getSignatureElement("DigestMethod", certDigestTag, true) == null) {
						signatureOK = false;
						validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found.signature",
								"DigestMethod", "Cert"));
					}

					if (getSignatureElement("DigestValue", certDigestTag, true) == null) {
						signatureOK = false;
						validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found.signature",
								"IssuerSerial", "Cert"));
					}

					if (getXadesElement("IssuerSerial", certTag, true) == null) {
						signatureOK = false;
						validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found.signature",
								"DigestValue", "Cert"));
					}
					Element signedDataObjectPropertiesTag = getXadesElement("SignedDataObjectProperties",
							signedPropertiesTag, true);
					if (signedDataObjectPropertiesTag == null) {
						signatureOK = false;
						validationWaring.add(xadesMessagesBundle.getString("error.xml.element.not.found.signature",
								"SignedDataObjectProperties", "Cert"));

					}

					// Element dataObjectFormatTag = getXadesElement("DataObjectFormat",
					// signedDataObjectPropertiesTag, true);
					// Element mimeTypeTag = getXadesElement("MimeType", dataObjectFormatTag, true);

					if (cert != null) {
						verifySignature(signatureTag, cert);
						Element signatureInfoTag = getSignatureElement("SignedInfo", signatureTag, true);
						Element signatureValueTag = getSignatureElement("SignatureValue", signatureTag, true);
						String signatureValue = signatureValueTag.getTextContent();
						verifyHash(signatureTag, signatureInfoTag, signatureValue, cert);
						if (sigPolicyId != null) {
							String signatureMethod = "";
							Element signatureMethodTag = getSignatureElement("SignatureMethod", signatureTag, true);
							if (signatureMethodTag != null) {
								signatureMethod = getAttribute(signatureMethodTag, "Algorithm", true);
							} else {
								validationErrors
										.add(xadesMessagesBundle.getString("error.xml.signature.method.not.found"));
								signatureOK = false;
							}

							Element sigPolicyIdIdentifier = getXadesElement("Identifier", sigPolicyId, true);
							if (sigPolicyIdIdentifier != null) {
								String strIdentifier = sigPolicyIdIdentifier.getTextContent();
								XMLSignaturePolicy xmlSignaturePolicy = verifyPolicy(signatureTag, strIdentifier,
										signatureMethod, signatureValue);
								sigInf.setSignaturePolicy(xmlSignaturePolicy);
								List<String> listMandetedUnsignedProperties = xmlSignaturePolicy.getXmlSignerRules()
										.getMandatedUnsignedQProperties();
								if (!listMandetedUnsignedProperties.isEmpty()) {
									VerifyMandatedUnsignedQProperties(listMandetedUnsignedProperties, signatureTag,
											signatureValue);
									sigInf.setTimeStampSigner(getVarTimestampToSignature());
									setVarTimestampToSignature(null);
								}
							} else {
								validationErrors.add(xadesMessagesBundle.getString("error.xml.policy.id.not.found"));
								signatureOK = false;
							}
						}
					}
				} else {
					validationWaring.add(xadesMessagesBundle.getString("error.xml.policy.id.not.found"));
					signatureOK = verifySignatureNoICPBrasil(signatureTag, cert);
				}
				sigInf.setValidatorErrors(validationErrors);
				sigInf.setValidatorWarnins(validationWaring);
				signaturesInfo.add(sigInf);

			}
		}
		return signatureOK;
	}

	private void VerifyMandatedUnsignedQProperties(List<String> listMandetedUnsignedProperties, Element signatureTag,
			String signatureValue) {
		for (String propertie : listMandetedUnsignedProperties) {
			switch (propertie) {
			case "SignatureTimeStamp":
				checkSignatureTimeStampPropertie(signatureTag, signatureValue);
				break;
			case "CompleteCertificateRefs":
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				break;
			case "CompleteRevocationRefs":
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				break;
			case "SigAndRefsTimeStamp":
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				break;
			case "CertificateValues":
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				break;
			case "RevocationValues":
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				break;
			case "ArchiveTimeStamp":
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				break;
			default:
				validationErrors.add(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));
				logger.error(xadesMessagesBundle.getString("error.attribute.not.implemented", propertie));

			}

		}
	}

	/**
	 * Verify TimeStamp on Signature
	 * @param signatureTag
	 * @param signatureValue
	 */
	private void checkSignatureTimeStampPropertie(Element signatureTag, String signatureValue) {

		try {
			Security.addProvider(new BouncyCastleProvider());
			String timeStampForSignature = signatureTag.getElementsByTagName("xades:EncapsulatedTimeStamp").item(0)
					.getTextContent();
			TimeStampOperator timeStampOperator = new TimeStampOperator();
			byte[] varTimeStamp = Base64.decode(timeStampForSignature);
			byte[] varSignature = Base64.decode(signatureValue);
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(varTimeStamp));
			Timestamp timeStampSigner = new Timestamp(timeStampToken);
			timeStampOperator.validate(varSignature, varTimeStamp, null);
			setVarTimestampToSignature(timeStampSigner);
		} catch (CertificateCoreException | IOException | TSPException | CMSException e) {
			setVarTimestampToSignature(null);
			validationErrors
					.add(xadesMessagesBundle.getString("error.xml.invalid.signature.timestamp", e.getMessage()));
		}
	}

	public List<XMLSignatureInformations> getSignaturesInfo() {
		return signaturesInfo;
	}

	public Timestamp getVarTimestampToSignature() {
		return varTimestampToSignature;
	}

	private void setVarTimestampToSignature(Timestamp varTimestampToSignature) {
		this.varTimestampToSignature = varTimestampToSignature;
	}

	/**
	 * Verify a Signature that not in according to the ICP-Brasil DOC-ICP-15
	 * @param signatureTag
	 * @param cert
	 * @return
	 */
	private boolean verifySignatureNoICPBrasil(Element signatureTag, X509Certificate cert ) {
		

		PublicKey publicKey = cert.getPublicKey();
		DOMValidateContext valContext = new DOMValidateContext(publicKey, signatureTag);
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
		XMLSignature signature = null;
		try {
			signature = fac.unmarshalXMLSignature(valContext);
		} catch (MarshalException e) {
			return false;
		}
		try {
			return signature.validate(valContext);
		} catch (XMLSignatureException e) {
			return false;
		}
	}


}
