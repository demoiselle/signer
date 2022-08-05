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
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * The CommonRules define rules that are common to all commitment types. These
 * rules are defined in terms of trust conditions for certificates, timestamps
 * and attributes, along with any constraints on attributes that may be included
 * in the electronic signature.
 *
 * <pre>
 * CommitmentRule ::= SEQUENCE {
 *     selCommitmentTypes  {@link SelectedCommitmentTypes},
 *     signerAndVeriferRules [0] {@link SignerAndVerifierRules} OPTIONAL,
 *     signingCertTrustCondition [1] {@link SigningCertTrustCondition} OPTIONAL,
 *     timeStampTrustCondition [2] {@link TimestampTrustCondition} OPTIONAL,
 *     attributeTrustCondition [3] {@link AttributeTrustCondition} OPTIONAL,
 *     algorithmConstraintSet [4] {@link AlgorithmConstraintSet} OPTIONAL,
 *     signPolExtensions [5] {@link SignPolExtensions} OPTIONAL
 * }
 * </pre>
 *
 * @author 07721825741
 *
 * @see ASN1Object
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DERTaggedObject
 */
public class CommonRules extends ASN1Object {

	private SignerAndVerifierRules signerAndVeriferRules;
	private SigningCertTrustCondition signingCertTrustCondition;
	private TimestampTrustCondition timeStampTrustCondition;
	private AttributeTrustCondition attributeTrustCondition;
	private AlgorithmConstraintSet algorithmConstraintSet;
	private SignPolExtensions signPolExtensions;

	public SignerAndVerifierRules getSignerAndVeriferRules() {
		return signerAndVeriferRules;
	}

	public void setSignerAndVeriferRules(
		SignerAndVerifierRules signerAndVeriferRules) {
		this.signerAndVeriferRules = signerAndVeriferRules;
	}

	public SigningCertTrustCondition getSigningCertTrustCondition() {
		return signingCertTrustCondition;
	}

	public void setSigningCertTrustCondition(
		SigningCertTrustCondition signingCertTrustCondition) {
		this.signingCertTrustCondition = signingCertTrustCondition;
	}

	public TimestampTrustCondition getTimeStampTrustCondition() {
		return timeStampTrustCondition;
	}

	public void setTimeStampTrustCondition(
		TimestampTrustCondition timeStampTrustCondition) {
		this.timeStampTrustCondition = timeStampTrustCondition;
	}

	public AttributeTrustCondition getAttributeTrustCondition() {
		return attributeTrustCondition;
	}

	public void setAttributeTrustCondition(
		AttributeTrustCondition attributeTrustCondition) {
		this.attributeTrustCondition = attributeTrustCondition;
	}

	public AlgorithmConstraintSet getAlgorithmConstraintSet() {
		return algorithmConstraintSet;
	}

	public void setAlgorithmConstraintSet(
		AlgorithmConstraintSet algorithmConstraintSet) {
		this.algorithmConstraintSet = algorithmConstraintSet;
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
		int total = derSequence.size();

		if (total > 0) {
			for (int i = 0; i < total; i++) {
				ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
				if (object instanceof DERTaggedObject) {
					DERTaggedObject derTaggedObject = (DERTaggedObject) object;
					TAG tag = TAG.getTag(derTaggedObject.getTagNo());
					switch (tag) {
						case signerAndVeriferRules:
							this.signerAndVeriferRules = new SignerAndVerifierRules();
							this.signerAndVeriferRules.parse(object);
							break;
						case signingCertTrustCondition:
							this.signingCertTrustCondition = new SigningCertTrustCondition();
							this.signingCertTrustCondition.parse(object);
							break;
						case timeStampTrustCondition:
							this.timeStampTrustCondition = new TimestampTrustCondition();
							this.timeStampTrustCondition.parse(object);
							break;
						case attributeTrustCondition:
							this.attributeTrustCondition = new AttributeTrustCondition();
							this.attributeTrustCondition.parse(object);
							break;
						case algorithmConstraintSet:
							this.algorithmConstraintSet = new AlgorithmConstraintSet();
							this.algorithmConstraintSet.parse(object);
							break;
						case signPolExtensions:
							this.signPolExtensions = new SignPolExtensions();
							this.signPolExtensions.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}
	}

	enum TAG {

		signerAndVeriferRules(0),
		signingCertTrustCondition(1),
		timeStampTrustCondition(2),
		attributeTrustCondition(3),
		algorithmConstraintSet(4),
		signPolExtensions(5);

		private final int value;

		TAG(int value) {
			this.value = value;
		}

		public static TAG getTag(int value) {
			for (TAG tag : TAG.values()) {
				if (tag.value == value) {
					return tag;
				}
			}
			return null;
		}
	}
}
