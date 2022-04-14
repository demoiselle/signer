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

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.Init;
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
import org.demoiselle.signer.policy.impl.xades.util.PolicyUtils;
import org.demoiselle.signer.policy.impl.xades.xml.UnsignedAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * 
 * On this step is created the only the Unsigned Attributes
 * 
 * This implementation is based in XAdEs standard, available in
 * https://www.w3.org/TR/XAdES/ and Brazilian digital signature standards
 * presented in
 * https://www.gov.br/iti/pt-br/centrais-de-conteudo/doc-icp-15-03-versao-7-4-req-das-pol-de-assin-dig-na-icp-brasil-pdf
 *
 * @author Fabiano Kuss &lt;fabiano.kuss@serpro.gov.br&gt;
 * @author Emerson Saito &lt;emerson.saito@serpro.gov.br&gt;
 */
public class XMLUnsignedAttributes implements UnsignedAttributes {

	public static final String XMLNS = "http://www.w3.org/2000/09/xmldsig#";
	public static final String XMLNS_DS = "xmlns:ds";
	public static final String XMLNS_XADES = "xmlns:xades";
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";
	private static final Logger logger = LoggerFactory.getLogger(XMLSigner.class);
	private static MessagesBundle xadesMessagesBundle = new MessagesBundle();
	private PrivateKey privateKey = null;
	private byte[] docSignature = null;
	private X509Certificate certificate;
	private Certificate certificateChain[] = null;
	private Document signedDocument = null;
	private String id = "id-" + System.currentTimeMillis();
	private PolicyFactory.Policies policy = null;
	private Date notAfterSignerCertificate;

	/**
	 * The default policy is AD_RT
	*/
	public XMLUnsignedAttributes() {
		this.policy = PolicyUtils.getPolicyByOid(XMLPoliciesOID.AD_RT_XADES_2_4.getOID());
	}
	
	
	@Override
	public Document doUnsignedAttributes(Document doc) {
		Init.init();

		Init.init();

		if (policy == null) {
			logger.error(xadesMessagesBundle.getString("error.policy.not.informed"));
			throw new XMLSignerException(xadesMessagesBundle.getString("error.policy.not.informed"));
		}

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
		setNotAfterSignerCertificate(pV.valDate(this.certificate));

		int numSignatures = doc.getElementsByTagName("ds:Signature").getLength() - 1;
		Element sigTag = (Element) doc.getElementsByTagName("ds:Signature").item(numSignatures);
		Element signatureValueTag = (Element) sigTag.getElementsByTagName("ds:SignatureValue").item(0);
		byte[] sigValue = Base64.decode(signatureValueTag.getTextContent());
		docSignature = sigValue;

		List<String> listMandetedUnsignedProperties = xMLPolicyValidator.getXmlSignaturePolicy().getXmlSignerRules()
				.getMandatedUnsignedQProperties();
		if (listMandetedUnsignedProperties.size() > 0) {
			Element unsignedProperties = createUnsignedProperties(doc, listMandetedUnsignedProperties);
			doc.getElementsByTagName("xades:QualifyingProperties").item(0).appendChild(unsignedProperties);
		}
		// sigTag.appendChild(objectTag);
		signedDocument = doc;
		return signedDocument;
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
		XMLTimeStampToken varXMLTimeStampToken = new XMLTimeStampToken(getPrivateKey(), getCertificateChain(),
				docSignature, null);
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

	public void setPolicyId(String policyOID) {
		this.policy = PolicyUtils.getPolicyByOid(policyOID);
	}

}
