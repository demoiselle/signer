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

package org.demoiselle.signer.policy.engine.xml.icpb;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.policy.engine.exception.PolicyException;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Validate if a policy is on valid period and not revoked.
 *
 * @author Emerson Sachio Saito &lt;emerson.saito@serpro.gov.br&gt;
 */
public class XMLPolicyValidator {

	private Document LPAXML = null;
	private Document xsp = null;
	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private static final Logger LOGGER = LoggerFactory.getLogger(XMLPolicyValidator.class);
	private final ConfigurationRepo config = ConfigurationRepo.getInstance();
	private XMLSignaturePolicy xmlSignaturePolicy = new XMLSignaturePolicy();
	public static final String XAdESv1_3_2 = "http://uri.etsi.org/01903/v1.3.2#";

	public XMLPolicyValidator(Document xsp) {
		super();
		this.xsp = xsp;
	}

	public boolean validate() {
		boolean valid = false;

		try {
			getXmlSignaturePolicy()
					.setPolicyIssuerName(xsp.getElementsByTagName("pa:PolicyIssuerName").item(0).getTextContent());
			getXmlSignaturePolicy()
					.setIdentifier(xsp.getElementsByTagName("XAdES:Identifier").item(0).getTextContent());
			getXmlSignaturePolicy()
					.setFieldOfApplication(xsp.getElementsByTagName("pa:FieldOfApplication").item(0).getTextContent());

			NodeList paSignerRules = xsp.getElementsByTagName("pa:SignerRules");
			XMLSignerRules xmlSignerRules = new XMLSignerRules();
			for (int i = 0; i < paSignerRules.getLength(); i++) {
				Element signerRule = (Element) paSignerRules.item(i);
				NodeList signerRuleNodeList = signerRule.getChildNodes();
				for (int j = 0; j < signerRuleNodeList.getLength(); j++) {
					Element signerRuleChild = (Element) signerRuleNodeList.item(j);
					String typeOfProperties = signerRuleChild.getNodeName();
					NodeList signerRuleChildNodeList = signerRuleChild.getChildNodes();
					for (int k = 0; k < signerRuleChildNodeList.getLength(); k++) {
						if (typeOfProperties.equalsIgnoreCase("pa:MandatedSignedQProperties")) {
							xmlSignerRules.getMandatedSignedQProperties()
									.add(signerRuleChildNodeList.item(k).getTextContent());
						}
						if (typeOfProperties.equalsIgnoreCase("pa:MandatedUnsignedQProperties")) {
							xmlSignerRules.getMandatedUnsignedQProperties()
									.add(signerRuleChildNodeList.item(k).getTextContent());
						}
					}
				}
			}
			getXmlSignaturePolicy().setXmlSignerRules(xmlSignerRules);

			NodeList algorithmConstraints = xsp.getElementsByTagName("pa:SignerAlgConstraints");
			for (int i = 0; i < algorithmConstraints.getLength(); i++) {
				Element algorithmConstraintElement = (Element) algorithmConstraints.item(i);
				NodeList algorithmConstraintNodeList = algorithmConstraintElement.getChildNodes();
				for (int j = 0; j < algorithmConstraintNodeList.getLength(); j++) {
					Element algAndLength = (Element) algorithmConstraintNodeList.item(j);
					NodeList algAndLengthNodeList = algAndLength.getChildNodes();
					XMLSignerAlgConstraint xmlSignerAlgConstraint = new XMLSignerAlgConstraint();
					for (int k = 0; k < algAndLengthNodeList.getLength(); k++) {
						Node childNode = algAndLengthNodeList.item(k);
						if (childNode.getNodeName().equalsIgnoreCase("pa:AlgId")) {
							xmlSignerAlgConstraint.setAlgId(childNode.getTextContent());
						}
						if (childNode.getNodeName().equalsIgnoreCase("pa:MinKeyLength")) {
							xmlSignerAlgConstraint.setMinKeyLength(childNode.getTextContent());
						}
					}
					getXmlSignaturePolicy().getXmlSignerAlgConstraintList().add(xmlSignerAlgConstraint);

				}
			}

			String xspNotBefore = xsp.getElementsByTagName("pa:NotBefore").item(0).getTextContent();
			String xspNotAfter = xsp.getElementsByTagName("pa:NotAfter").item(0).getTextContent();
			String xspDateOfIssue = xsp.getElementsByTagName("pa:DateOfIssue").item(0).getTextContent();
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
			Date xspNotBeforeDate = null;
			Date xspNotAfterDate = null;
			try {
				getXmlSignaturePolicy().setDateOfIssue(sdf.parse(xspDateOfIssue));
				xspNotBeforeDate = sdf.parse(xspNotBefore);
				getXmlSignaturePolicy().setNotBefore(xspNotBeforeDate);
				xspNotAfterDate = sdf.parse(xspNotAfter);
				getXmlSignaturePolicy().setNotAfter(xspNotAfterDate);

			} catch (ParseException e) {
				LOGGER.error(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
				throw new PolicyException(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
			}

			Date actualDate = new GregorianCalendar().getTime();
			if (actualDate.before(xspNotBeforeDate) || actualDate.after(xspNotAfterDate)) {
				LOGGER.error(policyMessagesBundle.getString("error.policy.valid.period", sdf.format(xspNotBeforeDate),
						sdf.format(xspNotAfterDate)));
				throw new PolicyException(policyMessagesBundle.getString("error.policy.valid.period",
						sdf.format(xspNotBeforeDate), sdf.format(xspNotAfterDate)));
			}
			PolicyFactory factory = PolicyFactory.getInstance();
			Document tempLPAXML = factory.loadLPAXAdES();
			setLPAXML(tempLPAXML);
			String lpaNextUpdate = tempLPAXML.getElementsByTagName("lpa:NextUpdate").item(0).getTextContent();
			Date lpaNextUpdateDate;
			try {
				lpaNextUpdateDate = sdf.parse(lpaNextUpdate);
			} catch (ParseException e) {
				LOGGER.error(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
				throw new PolicyException(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
			}
			if (actualDate.after(lpaNextUpdateDate)) {
				LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated", sdf.format(lpaNextUpdateDate)));
				LOGGER.debug(policyMessagesBundle.getString("info.lpa.load.local", config.getLpaPath()));
				tempLPAXML = factory.loadLPAXAdESLocal();
				if (tempLPAXML != null) {
					lpaNextUpdate = tempLPAXML.getElementsByTagName("lpa:NextUpdate").item(0).getTextContent();
					try {
						lpaNextUpdateDate = sdf.parse(lpaNextUpdate);
					} catch (ParseException e) {
						LOGGER.error(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
						throw new PolicyException(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
					}
					if (actualDate.after(lpaNextUpdateDate)) {
						LOGGER.debug(policyMessagesBundle.getString("error.policy.local.not.updated",
								config.getLpaPath() + "LPA_XAdES.xml", sdf.format(lpaNextUpdateDate)));
						tempLPAXML = factory.loadLPAXAdESUrl();
						if (tempLPAXML != null) {
							lpaNextUpdate = tempLPAXML.getElementsByTagName("lpa:NextUpdate").item(0).getTextContent();
							try {
								lpaNextUpdateDate = sdf.parse(lpaNextUpdate);
							} catch (ParseException e) {
								LOGGER.error(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
								throw new PolicyException(
										policyMessagesBundle.getString("error.date.parser", e.getMessage()));
							}
							if (actualDate.after(lpaNextUpdateDate)) {
								LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated",
										sdf.format(lpaNextUpdateDate)));
							} else {
								setLPAXML(tempLPAXML);
							}
						}
					} else {
						setLPAXML(tempLPAXML);
					}
				} else {
					tempLPAXML = factory.loadLPAXAdESUrl();
					if (tempLPAXML != null) {
						lpaNextUpdate = tempLPAXML.getElementsByTagName("lpa:NextUpdate").item(0).getTextContent();
						try {
							lpaNextUpdateDate = sdf.parse(lpaNextUpdate);
						} catch (ParseException e) {
							LOGGER.error(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
							throw new PolicyException(
									policyMessagesBundle.getString("error.date.parser", e.getMessage()));
						}
						if (actualDate.after(lpaNextUpdateDate)) {
							LOGGER.debug(policyMessagesBundle.getString("error.policy.not.updated",
									sdf.format(lpaNextUpdateDate)));
						} else {
							setLPAXML(tempLPAXML);
						}
					} else {
						LOGGER.warn(policyMessagesBundle.getString("error.lpa.not.found"));
					}
				}
			}

			Element policyIdentifier = (Element) xsp.getElementsByTagName("XAdES:Identifier").item(0);
			String textPolicyIdentifier = policyIdentifier.getTextContent();
			NodeList listPolicyInfo = LPAXML.getElementsByTagName("lpa:PolicyInfo");

			if (listPolicyInfo.getLength() > 0) {
				for (int i = 0; i < listPolicyInfo.getLength(); i++) {
					Element elementPolicyInfo = (Element) listPolicyInfo.item(i);
					NodeList policyInfochildNodeList = elementPolicyInfo.getChildNodes();
					for (int j = 0; j < policyInfochildNodeList.getLength(); j++) {
						Element elementPolicyInfochild = (Element) policyInfochildNodeList.item(j);
						Date policyRevogationDate = null;
						if (elementPolicyInfochild.getNodeName().equalsIgnoreCase("lpa:RevocationDate")) {
							try {
								policyRevogationDate = sdf.parse(elementPolicyInfochild.getTextContent());
							} catch (ParseException e) {
								LOGGER.error(policyMessagesBundle.getString("error.date.parser", e.getMessage()));
								throw new PolicyException(
										policyMessagesBundle.getString("error.date.parser", e.getMessage()));
							}
						}
						String textPolicyOID = "";
						if (elementPolicyInfochild.getNodeName().equalsIgnoreCase("lpa:policyOIDurn")
								|| elementPolicyInfochild.getNodeName().equalsIgnoreCase("lpa:policyOID")) {
							textPolicyOID = elementPolicyInfochild.getTextContent();
						}
						// Found a policy on LPA
						if (textPolicyOID.equalsIgnoreCase(textPolicyIdentifier)) {
							if (policyRevogationDate != null) {
								LOGGER.error(policyMessagesBundle.getString("error.policy.revocated",
										sdf.format(policyRevogationDate)));
								throw new PolicyException(policyMessagesBundle.getString("error.policy.revocated",
										sdf.format(policyRevogationDate)));
							}
							valid = true;
						}
					}
				}
			}

		} catch (Exception e) {
			return valid;
		}
		return valid;
	}

	private void setLPAXML(Document lPAXML) {
		LPAXML = lPAXML;
	}

	public XMLSignaturePolicy getXmlSignaturePolicy() {
		return xmlSignaturePolicy;
	}
}
