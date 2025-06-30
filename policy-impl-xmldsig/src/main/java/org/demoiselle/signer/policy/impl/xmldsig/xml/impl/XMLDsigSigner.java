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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;

import org.demoiselle.signer.core.CertificateManager;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.exception.CertificateValidatorCRLException;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.core.util.MessagesBundle;
import org.demoiselle.signer.core.validator.PeriodValidator;
import org.demoiselle.signer.policy.impl.xmldsig.XMLSignerException;
import org.demoiselle.signer.policy.impl.xmldsig.util.DocumentUtils;
import org.demoiselle.signer.policy.impl.xmldsig.xml.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

/**
 * This implementation is based in XMLDSig standard, available in
 * https://www.w3.org/TR/xmldsig-core/ 
 *
 * @author Eduardo &lt;edumg80@gmail.com&gt;
 */
public class XMLDsigSigner implements Signer {
	
	private static final Logger logger = LoggerFactory.getLogger(XMLDsigSigner.class);
	private static MessagesBundle messagesBundle = new MessagesBundle();
	
	private PrivateKey privateKey = null;
	private X509Certificate certificate;
	private Certificate[] certificateChain = null;
	private String referenceId = "";
	private String signatureAlgorithm = "SHA1withRSA";
	private String signatureDigest = "SHA-1";
	
	public Document signEnveloped(boolean isFileLocation, String fileNameSource) throws XMLSignerException {
		if (!isFileLocation) {
			logger.error(messagesBundle.getString("error.xml.false.to.file"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.false.to.file"));
		}

		if (fileNameSource == null || fileNameSource.isEmpty()) {
			logger.error(messagesBundle.getString("error.xml.file.null", "fileNameSource"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.file.null", "fileNameSource"));
		}
		if (!fileNameSource.substring(fileNameSource.lastIndexOf(".") + 1).equalsIgnoreCase("xml")) {
			logger.error(messagesBundle.getString("error.xml.not.valid.file"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.not.valid.file"));
		}
		Document varDocToSing = DocumentUtils.loadXMLDocument(fileNameSource,
			referenceId != null && referenceId.length() > 0);

		return this.signEnveloped(varDocToSing);
	}

	public Document signEnveloped(String xmlAsString) throws XMLSignerException {
		if (xmlAsString == null || xmlAsString.isEmpty()) {
			logger.error(messagesBundle.getString("error.xml.parameter.null", "String xmlAsString"));
			throw new XMLSignerException(
				messagesBundle.getString("error.xml.parameter.null", "String xmlAsString"));
		}
		return this.signEnveloped(DocumentUtils.loadXMLDocumentFromString(xmlAsString,
				referenceId != null && referenceId.length() > 0));
	}

	public Document signEnveloped(byte[] content) throws XMLSignerException {
		if (content == null || content.length <= 0) {
			logger.error(messagesBundle.getString("error.xml.parameter.null", "byte[] content"));
			throw new XMLSignerException(messagesBundle.getString("error.xml.parameter.null", "byte[] content"));
		}
		return this.signEnveloped(DocumentUtils.loadXMLDocument(content,
			referenceId != null && referenceId.length() > 0));
	}

	private Document signEnveloped(Document docToSign) throws XMLSignerException {
		
		signInputValidation();
		
        XMLSignatureFactory xmlSigFac = XMLSignatureFactory.getInstance("DOM");
        SignedInfo signedInfo = null;
        DOMSignContext dsc = null;
        XMLSignature signature = null;
		try {
			DigestMethod digestMethod = xmlSigFac.newDigestMethod(AlgorithmsValues.getSignatureDigest(signatureDigest), null);
			Transform envelopedMethod = xmlSigFac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
			CanonicalizationMethod canonMethod = xmlSigFac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
			Reference ref = xmlSigFac.newReference(referenceId.length() > 0 ? "#" + referenceId : referenceId, digestMethod, Arrays.asList(envelopedMethod, canonMethod), null, null);
			SignatureMethod sigMethod = xmlSigFac.newSignatureMethod(AlgorithmsValues.getSignatureAlgorithm(signatureAlgorithm), null);
			signedInfo = xmlSigFac.newSignedInfo(canonMethod, sigMethod, Arrays.asList(ref));
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			logger.error(messagesBundle.getString("error.no.algorithm", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.no.algorithm", e.getMessage()));
		}
		KeyInfoFactory kif = xmlSigFac.getKeyInfoFactory();
		List<Object> x509Content = new ArrayList<Object>();
		x509Content.add(certificate);
		X509Data xd = kif.newX509Data(x509Content);
		KeyInfo ki = kif.newKeyInfo(Arrays.asList(xd));
		
		dsc = new DOMSignContext(privateKey, docToSign.getDocumentElement());
		signature = xmlSigFac.newXMLSignature(signedInfo, ki);
		try {
			signature.sign(dsc);
		} catch (MarshalException | XMLSignatureException e) {
			if (e.getCause() instanceof URIReferenceException) {
				logger.error(messagesBundle.getString("error.xml.signature.resource.not.resolved", referenceId));
				throw new XMLSignerException(messagesBundle.getString("error.xml.signature.resource.not.resolved", referenceId));				
			}
			logger.error(messagesBundle.getString("error.xml.signature.exception", e.getMessage()));
			throw new XMLSignerException(messagesBundle.getString("error.xml.signature.exception", e.getMessage()));
		}
		
		return docToSign;
	}

	private void signInputValidation() {
		if (this.certificateChain == null) {
			logger.error(messagesBundle.getString("error.certificate.null"));
			throw new XMLSignerException(messagesBundle.getString("error.certificate.null"));
		}

		if (getPrivateKey() == null) {
			logger.error(messagesBundle.getString("error.privatekey.null"));
			throw new XMLSignerException(messagesBundle.getString("error.privatekey.null"));
		}

		// Completa os certificados ausentes da cadeia, se houver
		if (this.certificate == null && this.certificateChain != null && this.certificateChain.length > 0) {
			this.certificate = (X509Certificate) this.certificateChain[0];
		}

		this.certificateChain = CAManager.getInstance().getCertificateChainArray(this.certificate);

		if (this.certificateChain.length < 3) {
			logger.error(messagesBundle.getString("error.no.ca", this.certificate.getIssuerDN()));
			throw new XMLSignerException(messagesBundle.getString("error.no.ca", this.certificate.getIssuerDN()));
		}
		
		try {
			new CertificateManager(this.certificate);
		} catch (CertificateValidatorCRLException cvre) {
			logger.warn(cvre.getMessage());
			ConfigurationRepo config = ConfigurationRepo.getInstance();
			config.setOnline(true);
			try {
				new CertificateManager(this.certificate);
			} catch (CertificateValidatorCRLException cvre1) {
				logger.error(cvre1.getMessage());
				throw new CertificateValidatorCRLException(cvre1.getMessage());
			}
		}

		PeriodValidator pV = new PeriodValidator();
		pV.valDate(this.certificate);		
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

	public void setCertificateChain(Certificate[] certificateChain) {
		this.certificateChain = certificateChain;
	}
	
	public String getReferenceId() {
		return referenceId;
	}

	public void setReferenceId(String referenceId) {
		this.referenceId = referenceId == null ? "" : referenceId;
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

}
