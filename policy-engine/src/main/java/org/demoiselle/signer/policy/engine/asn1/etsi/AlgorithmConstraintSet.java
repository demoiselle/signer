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
 * The algorithmConstrains fields, if present, identifies the signing algorithms
 * (hash, public key cryptography, combined hash and public key cryptography)
 * that may be used for specific purposes and any minimum length. If this field
 * is not present then the policy applies no constraints.
 * <p>
 * AlgorithmConstraintSet ::= SEQUENCE { -- Algorithm constraints on:
 * <p>
 * signerAlgorithmConstraints [0] {@link AlgorithmConstraints} OPTIONAL, -- signer
 * eeCertAlgorithmConstraints [1] {@link AlgorithmConstraints} OPTIONAL, -- issuer of end entity certs
 * caCertAlgorithmConstraints [2] {@link AlgorithmConstraints} OPTIONAL, -- issuer of CA certificates
 * aaCertAlgorithmConstraints [3] {@link AlgorithmConstraints} OPTIONAL, -- Attribute Authority
 * tsaCertAlgorithmConstraints [4]{@link AlgorithmConstraints} OPTIONAL -- TimeStamping Authority -- }
 */
public class AlgorithmConstraintSet extends ASN1Object {

	public enum TAG {

		signerAlgorithmConstraints(0),
		eeCertAlgorithmConstraints(1),
		caCertAlgorithmConstraints(2),
		aaCertAlgorithmConstraints(3),
		tsaCertAlgorithmConstraints(4);

		private int value;

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

	private AlgorithmConstraints signerAlgorithmConstraints;
	private AlgorithmConstraints eeCertAlgorithmConstraints;
	private AlgorithmConstraints caCertAlgorithmConstraints;
	private AlgorithmConstraints aaCertAlgorithmConstraints;
	private AlgorithmConstraints tsaCertAlgorithmConstraints;

	public AlgorithmConstraints getSignerAlgorithmConstraints() {
		return signerAlgorithmConstraints;
	}

	public void setSignerAlgorithmConstraints(
		AlgorithmConstraints signerAlgorithmConstraints) {
		this.signerAlgorithmConstraints = signerAlgorithmConstraints;
	}

	public AlgorithmConstraints getEeCertAlgorithmConstraints() {
		return eeCertAlgorithmConstraints;
	}

	public void setEeCertAlgorithmConstraints(
		AlgorithmConstraints eeCertAlgorithmConstraints) {
		this.eeCertAlgorithmConstraints = eeCertAlgorithmConstraints;
	}

	public AlgorithmConstraints getCaCertAlgorithmConstraints() {
		return caCertAlgorithmConstraints;
	}

	public void setCaCertAlgorithmConstraints(
		AlgorithmConstraints caCertAlgorithmConstraints) {
		this.caCertAlgorithmConstraints = caCertAlgorithmConstraints;
	}

	public AlgorithmConstraints getAaCertAlgorithmConstraints() {
		return aaCertAlgorithmConstraints;
	}

	public void setAaCertAlgorithmConstraints(
		AlgorithmConstraints aaCertAlgorithmConstraints) {
		this.aaCertAlgorithmConstraints = aaCertAlgorithmConstraints;
	}

	public AlgorithmConstraints getTsaCertAlgorithmConstraints() {
		return tsaCertAlgorithmConstraints;
	}

	public void setTsaCertAlgorithmConstraints(
		AlgorithmConstraints tsaCertAlgorithmConstraints) {
		this.tsaCertAlgorithmConstraints = tsaCertAlgorithmConstraints;
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
						case signerAlgorithmConstraints:
							this.signerAlgorithmConstraints = new AlgorithmConstraints();
							this.signerAlgorithmConstraints.parse(object);
							break;
						case eeCertAlgorithmConstraints:
							this.eeCertAlgorithmConstraints = new AlgorithmConstraints();
							this.eeCertAlgorithmConstraints.parse(object);
							break;
						case caCertAlgorithmConstraints:
							this.caCertAlgorithmConstraints = new AlgorithmConstraints();
							this.caCertAlgorithmConstraints.parse(object);
							break;
						case aaCertAlgorithmConstraints:
							this.aaCertAlgorithmConstraints = new AlgorithmConstraints();
							this.aaCertAlgorithmConstraints.parse(object);
							break;
						case tsaCertAlgorithmConstraints:
							this.tsaCertAlgorithmConstraints = new AlgorithmConstraints();
							this.tsaCertAlgorithmConstraints.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}
	}

}
