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
 * The policyConstraints extension constrains path processing in two ways.
 * It can be used to prohibit policy mapping or require that each certificate
 * in a path contain an acceptable policy identifier.
 * The policyConstraints field, if present specifies requirement for explicit indication
 * of the certificate policy and/or the constraints on policy mapping.
 * <p>
 * PolicyConstraints ::= SEQUENCE {
 * requireExplicitPolicy [0] SkipCerts OPTIONAL,
 * inhibitPolicyMapping [1] SkipCerts OPTIONAL
 * }
 * <p>
 * {@link SkipCerts} ::= INTEGER (0..MAX)
 *
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DERTaggedObject
 * @see ASN1Object
 */
public class PolicyConstraints extends ASN1Object {

	enum TAG {

		requireExplicitPolicy(0), inhibitPolicyMapping(1);
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

	private SkipCerts requireExplicitPolicy;
	private SkipCerts inhibitPolicyMapping;

	public SkipCerts getRequireExplicitPolicy() {
		return requireExplicitPolicy;
	}

	public void setRequireExplicitPolicy(SkipCerts requireExplicitPolicy) {
		this.requireExplicitPolicy = requireExplicitPolicy;
	}

	public SkipCerts getInhibitPolicyMapping() {
		return inhibitPolicyMapping;
	}

	public void setInhibitPolicyMapping(SkipCerts inhibitPolicyMapping) {
		this.inhibitPolicyMapping = inhibitPolicyMapping;
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
						case requireExplicitPolicy:
							this.requireExplicitPolicy = new SkipCerts();
							this.requireExplicitPolicy.parse(object);
							break;
						case inhibitPolicyMapping:
							this.inhibitPolicyMapping = new SkipCerts();
							this.inhibitPolicyMapping.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}
	}

}
