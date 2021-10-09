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

package org.demoiselle.signer.policy.engine.asn1.icpb.v2;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.asn1.GeneralizedTime;
import org.demoiselle.signer.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.SigningPeriod;

/**
 * V2 definition on:
 * http://www.iti.gov.br/icp-brasil/repositorio/144-icp-brasil/repositorio/3974-artefatos-de-assinatura-digital
 * <p>
 * {@link SigningPeriod} signingPeriod;
 * {@link GeneralizedTime} revocationDate;
 * {@link ObjectIdentifier} policyOID;
 * String policyURI;
 * org.bouncycastle.asn1.esf.OtherHashAlgAndValue policyDigest;
 */
public class PolicyInfo extends ASN1Object {

	private SigningPeriod signingPeriod;
	private GeneralizedTime revocationDate;
	private ObjectIdentifier policyOID;
	private String policyURI;
	private OtherHashAlgAndValue policyDigest;

	public SigningPeriod getSigningPeriod() {
		return signingPeriod;
	}

	public void setSigningPeriod(SigningPeriod signingPeriod) {
		this.signingPeriod = signingPeriod;
	}

	public GeneralizedTime getRevocationDate() {
		return revocationDate;
	}

	public void setRevocationDate(GeneralizedTime revocationDate) {
		this.revocationDate = revocationDate;
	}

	public ObjectIdentifier getPolicyOID() {
		return policyOID;
	}

	public void setPolicyOID(ObjectIdentifier policyOID) {
		this.policyOID = policyOID;
	}

	public String getPolicyURI() {
		return policyURI;
	}

	public void setPolicyURI(String policyURI) {
		this.policyURI = policyURI;
	}

	public OtherHashAlgAndValue getPolicyDigest() {
		return policyDigest;
	}

	public void setPolicyDigest(OtherHashAlgAndValue policyDigest) {
		this.policyDigest = policyDigest;
	}

	@Override
	public void parse(ASN1Primitive primitive) {
		ASN1Sequence sequence1 = ASN1Object.getDERSequence(primitive);
		this.signingPeriod = new SigningPeriod();
		this.signingPeriod.parse(sequence1.getObjectAt(0).toASN1Primitive());
		int indice = 2;

		ASN1Primitive secondObject = sequence1.getObjectAt(1).toASN1Primitive();
		if (secondObject instanceof ASN1ObjectIdentifier) {
			indice = 1;
		}
		if (indice == 2) {
			this.revocationDate = new GeneralizedTime();
			this.revocationDate.parse(secondObject);
		}
		this.policyOID = new ObjectIdentifier();
		this.policyOID.parse(sequence1.getObjectAt(indice).toASN1Primitive());
		DERIA5String policyURI = (DERIA5String) sequence1.getObjectAt(indice + 1);
		this.policyURI = policyURI.getString();

		ASN1Primitive policyDigest = sequence1.getObjectAt(indice + 2).toASN1Primitive();
		ASN1Sequence sequence2 = ASN1Sequence.getInstance(policyDigest);

		DEROctetString derOctetString = (DEROctetString) sequence2.getObjectAt(1).toASN1Primitive();
		ASN1Sequence sequence3 = ASN1Object.getDERSequence(sequence2.getObjectAt(0).toASN1Primitive());
		ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) sequence3.getObjectAt(0).toASN1Primitive();
		AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(objectIdentifier);
		this.policyDigest = new OtherHashAlgAndValue(algorithmIdentifier, derOctetString);
	}
}
