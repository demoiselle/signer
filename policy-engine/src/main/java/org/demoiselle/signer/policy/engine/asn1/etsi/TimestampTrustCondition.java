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
 * The TimeStampTrustCondition field identifies trust conditions for
 * certificate path processing used to authenticate the timstamping
 * authority and constraints on the name of the timestamping authority.
 * This applies to the timestamp that shall be present in every ES-T.
 *
 * <pre>
 *     TimestampTrustCondition ::= SEQUENCE {
 *     ttsCertificateTrustTrees [0] {@link CertificateTrustTrees} OPTIONAL,
 *     ttsRevReq [1] {@link CertRevReq} OPTIONAL,
 *     ttsNameConstraints [2] {@link NameConstraints} OPTIONAL,
 *     cautionPeriod [3] {@link DeltaTime} OPTIONAL,
 *     signatureTimestampDelay [4] {@link DeltaTime} OPTIONAL
 *     }
 * </pre>
 */
public class TimestampTrustCondition extends ASN1Object {

	enum TAG {

		ttsCertificateTrustTrees(0),
		ttsRevReq(1),
		ttsNameConstraints(2),
		cautionPeriod(3),
		signatureTimestampDelay(4);

		int value;

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

	private CertificateTrustTrees ttsCertificateTrustTrees;
	private CertRevReq ttsRevReq;
	private NameConstraints ttsNameConstraints;
	private DeltaTime cautionPeriod;
	private DeltaTime signatureTimestampDelay;

	public CertificateTrustTrees getTtsCertificateTrustTrees() {
		return ttsCertificateTrustTrees;
	}

	public void setTtsCertificateTrustTrees(
		CertificateTrustTrees ttsCertificateTrustTrees) {
		this.ttsCertificateTrustTrees = ttsCertificateTrustTrees;
	}

	public CertRevReq getTtsRevReq() {
		return ttsRevReq;
	}

	public void setTtsRevReq(CertRevReq ttsRevReq) {
		this.ttsRevReq = ttsRevReq;
	}

	public NameConstraints getTtsNameConstraints() {
		return ttsNameConstraints;
	}

	public void setTtsNameConstraints(NameConstraints ttsNameConstraints) {
		this.ttsNameConstraints = ttsNameConstraints;
	}

	public DeltaTime getCautionPeriod() {
		return cautionPeriod;
	}

	public void setCautionPeriod(DeltaTime cautionPeriod) {
		this.cautionPeriod = cautionPeriod;
	}

	public DeltaTime getSignatureTimestampDelay() {
		return signatureTimestampDelay;
	}

	public void setSignatureTimestampDelay(DeltaTime signatureTimestampDelay) {
		this.signatureTimestampDelay = signatureTimestampDelay;
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
						case ttsCertificateTrustTrees:
							this.ttsCertificateTrustTrees = new CertificateTrustTrees();
							this.ttsCertificateTrustTrees.parse(object);
							break;
						case ttsRevReq:
							this.ttsRevReq = new CertRevReq();
							this.ttsRevReq.parse(object);
							break;
						case ttsNameConstraints:
							this.ttsNameConstraints = new NameConstraints();
							this.ttsNameConstraints.parse(object);
							break;
						case cautionPeriod:
							this.cautionPeriod = new DeltaTime();
							this.cautionPeriod.parse(object);
							break;
						case signatureTimestampDelay:
							this.signatureTimestampDelay = new DeltaTime();
							this.signatureTimestampDelay.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}
	}

}
