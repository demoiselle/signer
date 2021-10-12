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

/**
 * The signature validation policy defines for the signer
 * which data elements shall be present in the electronic
 * signature he provides and for the verifier which data
 * elements shall be present under that signature policy
 * for an electronic signature to be potentially valid.
 * The signature validation policy is described as follows:
 *
 * <pre>
 * SignatureValidationPolicy ::= SEQUENCE {
 *     signingPeriod {@link SigningPeriod},
 *     commonRules {@link CommonRules},
 *     commitmentRules {@link CommitmentRules},
 *     signPolExtensions {@link SignPolExtensions} OPTIONAL
 * }
 * </pre>
 *
 * @see ASN1Sequence
 * @see ASN1Primitive
 */
public class SignatureValidationPolicy extends ASN1Object {

	private SigningPeriod signingPeriod;
	private CommonRules commonRules;
	private CommitmentRules commitmentRules;
	private SignPolExtensions signPolExtensions;

	public SignPolExtensions getSignPolExtensions() {
		return signPolExtensions;
	}

	public void setSignPolExtensions(SignPolExtensions signPolExtensions) {
		this.signPolExtensions = signPolExtensions;
	}

	public SigningPeriod getSigningPeriod() {
		return signingPeriod;
	}

	public void setSigningPeriod(SigningPeriod signingPeriod) {
		this.signingPeriod = signingPeriod;
	}

	public CommonRules getCommonRules() {
		return commonRules;
	}

	public void setCommonRules(CommonRules commonRules) {
		this.commonRules = commonRules;
	}

	public CommitmentRules getCommitmentRules() {
		return commitmentRules;
	}

	public void setCommitmentRules(CommitmentRules commitmentRules) {
		this.commitmentRules = commitmentRules;
	}

	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

		this.signingPeriod = new SigningPeriod();
		this.signingPeriod.parse(derSequence.getObjectAt(0).toASN1Primitive());

		this.commonRules = new CommonRules();
		this.commonRules.parse(derSequence.getObjectAt(1).toASN1Primitive());

		this.commitmentRules = new CommitmentRules();
		this.commitmentRules.parse(derSequence.getObjectAt(2).toASN1Primitive());

		if (derSequence.size() == 4) {
			this.signPolExtensions = new SignPolExtensions();
			this.signPolExtensions.parse(derSequence.getObjectAt(3).toASN1Primitive());
		}
	}
}
