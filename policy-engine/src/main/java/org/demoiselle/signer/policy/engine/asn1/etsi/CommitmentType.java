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
 * A specific commitment type identifier shall not appear in more than one commitment rule.
 * <p>
 * CommitmentType ::= SEQUENCE {
 * identifier  {@link CommitmentTypeIdentifier},
 * fieldOfApplication [0]  {@link FieldOfApplication} OPTIONAL,
 * semantics [1] DirectoryString OPTIONAL }
 * <p>
 * The fieldOfApplication and semantics fields define the specific use
 * and meaning of the commitment within the overall field of application defined for the policy.
 *
 * @see ASN1Object
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DERTaggedObject
 */
public class CommitmentType extends ASN1Object {

	enum TAG {

		fieldOfApplication(0),
		semantics(1);

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

	private CommitmentTypeIdentifier identifier;
	private FieldOfApplication fieldOfApplication;
	private String semantics;

	public CommitmentTypeIdentifier getIdentifier() {
		return identifier;
	}

	public void setIdentifier(CommitmentTypeIdentifier identifier) {
		this.identifier = identifier;
	}

	public FieldOfApplication getFieldOfApplication() {
		return fieldOfApplication;
	}

	public void setFieldOfApplication(FieldOfApplication fieldOfApplication) {
		this.fieldOfApplication = fieldOfApplication;
	}

	public String getSemantics() {
		return semantics;
	}

	public void setSemantics(String semantics) {
		this.semantics = semantics;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

		this.identifier = new CommitmentTypeIdentifier();
		this.identifier.parse(derSequence.getObjectAt(0).toASN1Primitive());

		int total = derSequence.size();

		if (total > 0) {
			for (int i = 0; i < total; i++) {
				ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
				if (object instanceof DERTaggedObject) {
					DERTaggedObject derTaggedObject = (DERTaggedObject) object;
					TAG tag = TAG.getTag(derTaggedObject.getTagNo());
					switch (tag) {
						case fieldOfApplication:
							this.fieldOfApplication = new FieldOfApplication();
							this.fieldOfApplication.parse(object);
							break;
						case semantics:
							break;
						default:
							break;
					}
				}
			}
		}
	}

}
