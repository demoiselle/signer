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
 * If the attributeTrustCondition field is not present then any
 * certified attributes may not be considered to be valid under
 * this validation policy.
 *
 * <pre>
 * AttributeTrustCondition ::= SEQUENCE {*
 *     attributeMandated BOOLEAN, -- Attribute shall be present
 *     HowCertAttribute
 *     CertificateTrustTrees OPTIONAL
 *     CertRevReq OPTIONAL
 *     AttributeConstraints OPTIONAL
 * }
 * </pre>
 */
public class AttributeTrustCondition extends ASN1Object {

	enum TAG {

		attrCertificateTrustTrees(0), attrRevReq(1), attributeConstraints(2);
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

	private Boolean attributeMandated;
	private HowCertAttribute howCertAttribute;
	private CertificateTrustTrees attrCertificateTrustTrees;
	private CertRevReq attrRevReq;
	private AttributeConstraints attributeConstraints;

	public Boolean getAttributeMandated() {
		return attributeMandated;
	}

	public void setAttributeMandated(Boolean attributeMandated) {
		this.attributeMandated = attributeMandated;
	}

	public HowCertAttribute getHowCertAttribute() {
		return howCertAttribute;
	}

	public void setHowCertAttribute(HowCertAttribute howCertAttribute) {
		this.howCertAttribute = howCertAttribute;
	}

	public CertificateTrustTrees getAttrCertificateTrustTrees() {
		return attrCertificateTrustTrees;
	}

	public void setAttrCertificateTrustTrees(
		CertificateTrustTrees attrCertificateTrustTrees) {
		this.attrCertificateTrustTrees = attrCertificateTrustTrees;
	}

	public CertRevReq getAttrRevReq() {
		return attrRevReq;
	}

	public void setAttrRevReq(CertRevReq attrRevReq) {
		this.attrRevReq = attrRevReq;
	}

	public AttributeConstraints getAttributeConstraints() {
		return attributeConstraints;
	}

	public void setAttributeConstraints(AttributeConstraints attributeConstraints) {
		this.attributeConstraints = attributeConstraints;
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
						case attrCertificateTrustTrees:
							this.attrCertificateTrustTrees = new CertificateTrustTrees();
							this.attrCertificateTrustTrees.parse(object);
							break;
						case attrRevReq:
							this.attrRevReq = new CertRevReq();
							this.attrRevReq.parse(object);
							break;
						case attributeConstraints:
							this.attributeConstraints = new AttributeConstraints();
							this.attributeConstraints.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}
		super.parse(derObject);
	}

}
