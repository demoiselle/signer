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

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 *
 * <pre>
 *     AlgAndLength ::= SEQUENCE {
 *        algID {@link ObjectIdentifier} ,
 *        minKeyLength INTEGER
 *        OPTIONAL,
 *        -- Minimum key length in bits other SignPolExtensions OPTIONAL
 *     }
 * </pre>
 *
 * @author 09275643784
 */
public class AlgAndLength extends ASN1Object {

	private ObjectIdentifier algID;
	private Integer minKeyLength;
	private SignPolExtensions other;

	public ObjectIdentifier getAlgID() {
		return algID;
	}

	public void setAlgID(ObjectIdentifier algID) {
		this.algID = algID;
	}

	public Integer getMinKeyLength() {
		return minKeyLength;
	}

	public void setMinKeyLength(Integer minKeyLength) {
		this.minKeyLength = minKeyLength;
	}

	public SignPolExtensions getOther() {
		return other;
	}

	public void setOther(SignPolExtensions other) {
		this.other = other;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		this.algID = new ObjectIdentifier();
		this.algID.parse(derSequence.getObjectAt(0).toASN1Primitive());
		if (derSequence.size() >= 2) {
			ASN1Integer derInteger = (ASN1Integer) derSequence.getObjectAt(1).toASN1Primitive();
			this.setMinKeyLength(derInteger.getValue().intValue());
		}
		if (derSequence.size() == 3) {
			this.other = new SignPolExtensions();
			this.other.parse(derSequence.getObjectAt(2).toASN1Primitive());
		}
	}

}
