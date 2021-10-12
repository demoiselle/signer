/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
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

package org.demoiselle.signer.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.asn1.GeneralizedTime;

/**
 * ETSI TR 102 272 V1.1.1 (2003-12)
 *
 * <pre>
 * SignPolicyInfo ::= SEQUENCE {
 * 				signPolicyIdentifier {@link SignPolicyId},
 * 				dateOfIssue {@link GeneralizedTime},
 * 				policyIssuerName {@link PolicyIssuerName},
 * 				fieldOfApplication {@link FieldOfApplication},
 * 				signatureValidationPolicy {@link SignatureValidationPolicy},
 * 				signPolExtensions {@link SignPolExtensions} OPTIONAL
 * }
 * </pre>
 *
 * @see ASN1Sequence
 * @see ASN1Primitive
 */
public class SignPolicyInfo extends ASN1Object {

	private SignPolicyId signPolicyIdentifier;
	private GeneralizedTime dateOfIssue;
	private PolicyIssuerName policyIssuerName;
	private FieldOfApplication fieldOfApplication;
	private SignatureValidationPolicy signatureValidationPolicy;
	private SignPolExtensions signPolExtensions;

	public SignPolicyId getSignPolicyIdentifier() {
		return signPolicyIdentifier;
	}

	public void setSignPolicyIdentifier(SignPolicyId signPolicyIdentifier) {
		this.signPolicyIdentifier = signPolicyIdentifier;
	}

	public GeneralizedTime getDateOfIssue() {
		return dateOfIssue;
	}

	public void setDateOfIssue(GeneralizedTime dateOfIssue) {
		this.dateOfIssue = dateOfIssue;
	}

	public PolicyIssuerName getPolicyIssuerName() {
		return policyIssuerName;
	}

	public void setPolicyIssuerName(PolicyIssuerName policyIssuerName) {
		this.policyIssuerName = policyIssuerName;
	}

	public FieldOfApplication getFieldOfApplication() {
		return fieldOfApplication;
	}

	public void setFieldOfApplication(FieldOfApplication fieldOfApplication) {
		this.fieldOfApplication = fieldOfApplication;
	}

	public SignatureValidationPolicy getSignatureValidationPolicy() {
		return signatureValidationPolicy;
	}

	public void setSignatureValidationPolicy(
		SignatureValidationPolicy signatureValidationPolicy) {
		this.signatureValidationPolicy = signatureValidationPolicy;
	}

	public SignPolExtensions getSignPolExtensions() {
		return signPolExtensions;
	}

	public void setSignPolExtensions(SignPolExtensions signPolExtensions) {
		this.signPolExtensions = signPolExtensions;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		this.signPolicyIdentifier = new SignPolicyId();
		this.signPolicyIdentifier.parse(derSequence.getObjectAt(0).toASN1Primitive());

		this.dateOfIssue = new GeneralizedTime();
		this.dateOfIssue.parse(derSequence.getObjectAt(1).toASN1Primitive());

		this.policyIssuerName = new PolicyIssuerName();
		this.policyIssuerName.parse(derSequence.getObjectAt(2).toASN1Primitive());

		this.fieldOfApplication = new FieldOfApplication();
		this.fieldOfApplication.parse(derSequence.getObjectAt(3).toASN1Primitive());

		this.signatureValidationPolicy = new SignatureValidationPolicy();
		this.signatureValidationPolicy.parse(derSequence.getObjectAt(4).toASN1Primitive());

		if (derSequence.size() == 6) {
			this.signPolExtensions = new SignPolExtensions();
			this.signPolExtensions.parse(derSequence.getObjectAt(5).toASN1Primitive());
		}
	}
}
