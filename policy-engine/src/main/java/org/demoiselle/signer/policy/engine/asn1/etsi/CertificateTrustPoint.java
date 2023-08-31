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

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * parse an org.bouncycastle.asn1.ASN1Primitive to get
 * <p>
 * trustpoint Certificate, -- self-signed certificate   @see X509Certificate
 * {@link PathLenConstraint } OPTIONAL,
 * {@link AcceptablePolicySet } OPTIONAL, -- If not present "any policy"
 * {@link NameConstraints } OPTIONAL,
 * {@link PolicyConstraints } OPTIONAL
 *
 * @see ASN1Primitive
 * @see ASN1Sequence
 */
public class CertificateTrustPoint extends ASN1Object {

	enum TAG {

		pathLenConstraint(0), acceptablePolicySet(1), nameConstraints(2), policyConstraints(3);
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

	private X509Certificate trustpoint;
	private PathLenConstraint pathLenConstraint;
	private AcceptablePolicySet acceptablePolicySet;
	private NameConstraints nameConstraints;
	private PolicyConstraints policyConstraints;

	public X509Certificate getTrustpoint() {
		return trustpoint;
	}

	public void setTrustpoint(X509Certificate trustpoint) {
		this.trustpoint = trustpoint;
	}

	public PathLenConstraint getPathLenConstraint() {
		return pathLenConstraint;
	}

	public void setPathLenConstraint(PathLenConstraint pathLenConstraint) {
		this.pathLenConstraint = pathLenConstraint;
	}

	public AcceptablePolicySet getAcceptablePolicySet() {
		return acceptablePolicySet;
	}

	public void setAcceptablePolicySet(AcceptablePolicySet acceptablePolicySet) {
		this.acceptablePolicySet = acceptablePolicySet;
	}

	public NameConstraints getNameConstraints() {
		return nameConstraints;
	}

	public void setNameConstraints(NameConstraints nameConstraints) {
		this.nameConstraints = nameConstraints;
	}

	public PolicyConstraints getPolicyConstraints() {
		return policyConstraints;
	}

	public void setPolicyConstraints(PolicyConstraints policyConstraints) {
		this.policyConstraints = policyConstraints;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		DERSequence x509Sequence = (DERSequence) derSequence.getObjectAt(0).toASN1Primitive();
		try {
			ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(x509Sequence.getEncoded());
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			 CertificateFactory fact = CertificateFactory.getInstance("X.509", "BC");
			  X509Certificate x509Cert = (X509Certificate) fact.generateCertificate(byteArrayInputStream);
			this.trustpoint = x509Cert;
		} catch (Throwable error) {
			error.printStackTrace();
		}

		int total = derSequence.size();

		if (total > 0) {
			for (int i = 0; i < total; i++) {
				ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
				if (object instanceof DERTaggedObject) {
					DERTaggedObject derTaggedObject = (DERTaggedObject) object;
					TAG tag = TAG.getTag(derTaggedObject.getTagNo());
					switch (tag) {
						case pathLenConstraint:
							this.pathLenConstraint = new PathLenConstraint();
							this.pathLenConstraint.parse(object);
							break;
						case acceptablePolicySet:
							this.acceptablePolicySet = new AcceptablePolicySet();
							this.acceptablePolicySet.parse(object);
							break;
						case nameConstraints:
							this.nameConstraints = new NameConstraints();
							this.nameConstraints.parse(object);

							break;
						case policyConstraints:
							this.policyConstraints = new PolicyConstraints();
							this.policyConstraints.parse(object);
							break;
						default:
							break;
					}
				}
			}
		}
	}

}
