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
import org.bouncycastle.asn1.DEROctetString;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * In this structure the policy information is preceded by
 * an identifier for the hashing algorithm used to protect
 * the signature policy and followed by the hash value which
 * shall be re-calculated and checked whenever the policy is
 * passed between the issuer and signer/verifier. The hash is
 * calculated without the outer type and length fields.
 *
 * <pre>
 * SignaturePolicy ::= SEQUENCE {
 *     signPolicyHashAlg AlgorithmIdentifier,
 *     signPolicyInfo SignPolicyInfo,
 *     signPolicyHash SignPolicyHash OPTIONAL
 * }
 * </pre>
 *
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DEROctetString
 */
public class SignaturePolicy {

	private AlgorithmIdentifier signPolicyHashAlg;
	private SignPolicyInfo signPolicyInfo;
	private SignPolicyHash signPolicyHash;
	private String signPolicyURI;
	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");

	public AlgorithmIdentifier getSignPolicyHashAlg() {
		return signPolicyHashAlg;
	}

	public void setSignPolicyHashAlg(AlgorithmIdentifier signPolicyHashAlg) {
		this.signPolicyHashAlg = signPolicyHashAlg;
	}

	public SignPolicyInfo getSignPolicyInfo() {
		return signPolicyInfo;
	}

	public void setSignPolicyInfo(SignPolicyInfo signPolicyInfo) {
		this.signPolicyInfo = signPolicyInfo;
	}

	public SignPolicyHash getSignPolicyHash() {
		return signPolicyHash;
	}

	public void setSignPolicyHash(SignPolicyHash signPolicyHash) {
		this.signPolicyHash = signPolicyHash;
	}

	public String getSignPolicyURI() {
		return signPolicyURI;
	}

	public void setSignPolicyURI(String signPolicyURI) {
		this.signPolicyURI = signPolicyURI;
	}

	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		this.signPolicyHashAlg = new AlgorithmIdentifier();
		this.signPolicyHashAlg.parse(derSequence.getObjectAt(0).toASN1Primitive());
		this.signPolicyInfo = new SignPolicyInfo();
		this.signPolicyInfo.parse(derSequence.getObjectAt(1).toASN1Primitive());
		if (derSequence.size() == 3) {
			this.signPolicyHash = new SignPolicyHash((DEROctetString) derSequence.getObjectAt(2));
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(policyMessagesBundle.getString("text.uri")).append(this.getSignPolicyURI()).append("\n");
		builder.append(policyMessagesBundle.getString("text.algo.hash")).append(this.getSignPolicyHashAlg().getAlgorithm().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.hash")).append(this.getSignPolicyHash().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.oid")).append(this.getSignPolicyInfo().getSignPolicyIdentifier().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.launch.date")).append(this.getSignPolicyInfo().getDateOfIssue().getDate()).append("\n");
		builder.append(policyMessagesBundle.getString("text.issuer")).append(this.getSignPolicyInfo().getPolicyIssuerName()).append("\n");
		builder.append(policyMessagesBundle.getString("text.application")).append(this.getSignPolicyInfo().getFieldOfApplication().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.valid")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()).append("\n");
		builder.append(policyMessagesBundle.getString("text.external")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getExternalSignedData()).append("\n");
		builder.append(policyMessagesBundle.getString("text.mandated.ref")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef()).append("\n");
		builder.append(policyMessagesBundle.getString("text.mandated.info")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo()).append("\n");

		for (AlgAndLength oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getAlgorithmConstraintSet().getSignerAlgorithmConstraints().getAlgAndLengths()) {
			builder.append(policyMessagesBundle.getString("text.algo")).append(oi.getAlgID()).append("\n");
			builder.append(policyMessagesBundle.getString("text.key.min.size")).append(oi.getMinKeyLength()).append("\n");
		}

		builder.append("==============================================================").append("\n");
		for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers()) {
			builder.append(policyMessagesBundle.getString("text.signed.attr.oid")).append(oi.getValue()).append("\n");
		}

		builder.append("==============================================================").append("\n");

		if (this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
			for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
				builder.append(policyMessagesBundle.getString("text.unsigned.attr.oid")).append(oi.getValue()).append("\n");
			}
		}

		if (this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
			builder.append("==============================================================").append("\n");
			for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
				builder.append(policyMessagesBundle.getString("text.unsigned.attr.oid")).append(oi.getValue()).append("\n");
			}
		}

		return builder.toString();
	}
}
