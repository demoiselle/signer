/*
 * Demoiselle Framework
 * Copyright (C) 2025 SERPRO
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

package org.demoiselle.signer.policy.impl.xmldsig.xml.impl;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateRevocationException;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.exception.CertificateValidatorException;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.CRLValidator;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.impl.xmldsig.XMLSignatureInformations;
import org.demoiselle.signer.policy.impl.xmldsig.XMLSignerException;
import org.demoiselle.signer.policy.impl.xmldsig.util.DocumentUtils;
import org.demoiselle.signer.policy.impl.xmldsig.xml.Checker;
import org.demoiselle.signer.policy.impl.xmldsig.xml.impl.CertificateKeySelector.CertificateSelectorResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This implementation is based in XMLDSig standard, available in
 * https://www.w3.org/TR/xmldsig-core/
 *
 * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public class XMLChecker implements Checker {
	
	private static final Logger logger = LoggerFactory.getLogger(XMLChecker.class);
	private static MessagesBundle messagesBundle = new MessagesBundle();
	
	private List<XMLSignatureInformations> signaturesInfo = new ArrayList<XMLSignatureInformations>();
	
	public boolean check(boolean isFileLocation, String xmlSignedFile) throws XMLSignerException {

		if (!isFileLocation) {
			logger.error(messagesBundle.getString("error.xml.false.to.file"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.false.to.file"));
		}

		if (xmlSignedFile == null || xmlSignedFile.isEmpty()) {
			logger.error(messagesBundle.getString("error.xml.file.null", "xmlSignedFile"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.file.null", "xmlSignedFile"));
		}
		if (!xmlSignedFile.substring(xmlSignedFile.lastIndexOf(".") + 1).equalsIgnoreCase("xml")) {
			logger.error(messagesBundle.getString("error.xml.not.valid.file"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.not.valid.file"));
		}

		Document doc = DocumentUtils.loadXMLDocument(xmlSignedFile, false);
		return verify(doc);
	}

	public boolean check(byte[] docData) throws XMLSignerException {
		if (docData == null || docData.length <= 0) {
			logger.error(messagesBundle.getString("error.xml.parameter.null", "byte[] docData"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parameter.null", "byte[] docData"));
		}
		Document doc = DocumentUtils.loadXMLDocument(docData, false);
		return verify(doc);
	}

	public boolean check(String xmlAsString) throws XMLSignerException {

		if (xmlAsString == null || xmlAsString.isEmpty()) {
			logger.error(messagesBundle.getString("error.xml.string.file.null", "String xmlAsString"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.file.null", "String xmlAsString"));
		}

		Document doc = DocumentUtils.loadXMLDocumentFromString(xmlAsString, false);
		return verify(doc);
	}

	private boolean verify(Document doc) {
		NodeList root = doc.getChildNodes();
		NodeList signatureListTags = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

		if (root.item(0) == signatureListTags.item(0)) {
			logger.error(messagesBundle.getString("error.xml.detached.content"));
			XMLSignatureInformations sigInf = new XMLSignatureInformations();
			sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.detached.content"));
			signaturesInfo.add(sigInf);
			return false;
		}
		int sizeSigList = signatureListTags.getLength();
		if (sizeSigList < 1) {
			logger.error(messagesBundle.getString("error.xml.signature.not.found"));
			XMLSignatureInformations sigInf = new XMLSignatureInformations();
			sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.signature.not.found"));
			signaturesInfo.add(sigInf);
			return false;
		}
		if (DocumentUtils.hasAnyDocumentElementAttribute(doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference"), "URI")) {
			DocumentUtils.setDocumentElementId(doc);
		}

		boolean verifyAllResult = true;
		for (int s = 0; s < sizeSigList; s++) {
			XMLSignatureInformations sigInf = new XMLSignatureInformations();
			signaturesInfo.add(sigInf);
			Element signatureTag = (Element) signatureListTags.item(s);
			XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
			DOMValidateContext valContext = new DOMValidateContext(new CertificateKeySelector(), signatureTag);
			valContext.setProperty("org.jcp.xml.dsig.secureValidation", true);
			XMLSignature signature;
			try {
				signature = signatureFactory.unmarshalXMLSignature(valContext);
			} catch (MarshalException e) {
				verifyAllResult = false;
				sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.document.fail"));
				continue;
			}
			boolean sigValid = false;
			try {
				sigValid = signature.validate(valContext);
			} catch (XMLSignatureException e) {
				verifyAllResult = false;
				// verify if exception comes from CertificateKeySelector class
				if (e.getMessage().contains("keyselector")) {
					logger.error(messagesBundle.getString("error.invalid.certificate"));
					sigInf.getValidatorErrors().add(messagesBundle.getString("error.invalid.certificate"));
				} else {
					logger.error(messagesBundle.getString("error.xml.signature.exception"));
					sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.signature.exception"));
				}
				continue;
			}
			verifyAllResult &= sigValid;

			CertificateSelectorResult cert = (CertificateSelectorResult) signature.getKeySelectorResult();
			verifyCertificate(cert.getCertificate(), sigInf);
			
			if (!sigValid) {
				try {
					if (!signature.getSignatureValue().validate(valContext)) {
						sigInf.setInvalidSignature(true);
						sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.signature.invalid"));
					}
					if (!signature.getSignedInfo().getReferences().isEmpty()) {
						Reference signRef = (Reference) signature.getSignedInfo().getReferences().get(0);
						if (!signRef.validate(valContext)) {
							sigInf.setInvalidSignature(true);
							sigInf.setReferenceId(signRef.getURI());
							sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.digest.invalid"));
						}						
					}
				} catch (XMLSignatureException e) {
					logger.error(messagesBundle.getString("error.xml.signature.exception"));
					sigInf.getValidatorErrors().add(messagesBundle.getString("error.xml.signature.exception"));
				}
			}
		}

		return verifyAllResult;
	}
	
	private void verifyCertificate(Certificate varCert, XMLSignatureInformations sigInf) {
		X509Certificate varX509Cert = null;
		try {
			varX509Cert = (X509Certificate) varCert;
		} catch (ClassCastException cce) {
			logger.error("Certificate is not an X509 Certificate.");
			sigInf.getValidatorErrors().add(messagesBundle.getString("error.certificate.exception"));
			return;
		}
		CRLValidator cV = new CRLValidator();
		try {
			cV.validate(varX509Cert);
		} catch (CertificateValidatorCRLException cvce) {
			logger.error(cvce.getMessage());
			sigInf.getValidatorErrors().add(cvce.getMessage());
		} catch (CertificateRevocationException cre) {
			logger.error("certificado revogado");
			sigInf.getValidatorErrors().add(messagesBundle.getString("error.certificate.repealed", cre.getMessage()));
		} catch (ClassCastException cce) {
		}

		PeriodValidator pV = new PeriodValidator();
		try {
			pV.valDate(varX509Cert);
		} catch (CertificateValidatorException cve) {
			sigInf.getValidatorWarnins().add(cve.getMessage());
			logger.warn(cve.getMessage());
		}
		
		try {
			LinkedList<X509Certificate> varChain = (LinkedList<X509Certificate>) CAManager.getInstance().getCertificateChain(varX509Cert);
			sigInf.setChain(varChain);
		} catch (Exception e) {
			sigInf.getValidatorErrors().add(e.getMessage());
		}
		sigInf.setIcpBrasilcertificate(new BasicCertificate(varX509Cert));					
		sigInf.setNotAfter(varX509Cert.getNotAfter());
	}

	public List<XMLSignatureInformations> getSignaturesInfo() {
		return signaturesInfo;
	}	

}
