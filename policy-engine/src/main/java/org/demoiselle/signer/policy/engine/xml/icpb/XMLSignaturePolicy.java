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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * Class to represent an XML Signature Policy
 *
 * @author Emerson Sachio Saito &lt;emerson.saito@serpro.gov.br&gt;
 */
public class XMLSignaturePolicy {

	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private String policyIssuerName = null;
	private Date notBefore = null;
	private Date notAfter = null;
	private Date dateOfIssue = null;
	private String identifier = null;
	private String fieldOfApplication = null;
	private List<XMLSignerAlgConstraint> xmlSignerAlgConstraintList = new ArrayList<XMLSignerAlgConstraint>();
	private XMLSignerRules xmlSignerRules = new XMLSignerRules();

	public String getPolicyIssuerName() {
		return policyIssuerName;
	}

	public void setPolicyIssuerName(String policyIssuerName) {
		this.policyIssuerName = policyIssuerName;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(Date notAfter) {
		this.notAfter = notAfter;
	}

	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public Date getDateOfIssue() {
		return dateOfIssue;
	}

	public void setDateOfIssue(Date dateOfIssue) {
		this.dateOfIssue = dateOfIssue;
	}

	public String getFieldOfApplication() {
		return fieldOfApplication;
	}

	public void setFieldOfApplication(String fieldOfApplication) {
		this.fieldOfApplication = fieldOfApplication;
	}

	public List<XMLSignerAlgConstraint> getXmlSignerAlgConstraintList() {
		return xmlSignerAlgConstraintList;
	}

	public void setXmlSignerAlgConstraintList(List<XMLSignerAlgConstraint> xmlSignerAlgConstraintList) {
		this.xmlSignerAlgConstraintList = xmlSignerAlgConstraintList;
	}

	public XMLSignerRules getXmlSignerRules() {
		return xmlSignerRules;
	}

	public void setXmlSignerRules(XMLSignerRules xmlSignerRules) {
		this.xmlSignerRules = xmlSignerRules;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		//builder.append(policyMessagesBundle.getString("text.uri")).append(this.getSignPolicyURI()).append("\n");
		//builder.append(policyMessagesBundle.getString("text.algo.hash")).append(this.getSignPolicyHashAlg().getAlgorithm().getValue()).append("\n");
		//builder.append(policyMessagesBundle.getString("text.hash")).append(this.getSignPolicyHash().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.oid")).append(this.getIdentifier()).append("\n");		
		builder.append(policyMessagesBundle.getString("text.launch.date")).append(this.getDateOfIssue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.issuer")).append(this.getPolicyIssuerName()).append("\n");
		builder.append(policyMessagesBundle.getString("text.application")).append(this.getFieldOfApplication()).append("\n");
		builder.append(policyMessagesBundle.getString("text.valid")).append(this.getNotAfter()).append(this.getNotBefore()).append("\n");
		//builder.append(policyMessagesBundle.getString("text.external")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getExternalSignedData()).append("\n");
		//builder.append(policyMessagesBundle.getString("text.mandated.ref")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef()).append("\n");
		// builder.append(policyMessagesBundle.getString("text.mandated.info")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo()).append("\n");

		for (XMLSignerAlgConstraint sac : getXmlSignerAlgConstraintList()) {
			builder.append(policyMessagesBundle.getString("text.algo")).append(sac.getAlgId()).append("\n");
			builder.append(policyMessagesBundle.getString("text.key.min.size")).append(sac.getMinKeyLength()).append("\n");
		}

		builder.append("==============================================================").append("\n");
		for (String sr : xmlSignerRules.getMandatedSignedQProperties()) {
			builder.append(policyMessagesBundle.getString("text.signed.attr")).append(sr).append("\n");
		}

		builder.append("==============================================================").append("\n");

		for (String sr : xmlSignerRules.getMandatedUnsignedQProperties()) {
			builder.append(policyMessagesBundle.getString("text.unsigned.attr")).append(sr).append("\n");
		}

		return builder.toString();
	}
}
