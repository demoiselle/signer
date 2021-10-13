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
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * If the SelectedCommitmentTypes indicates "empty" then this rule applied when a commitment type
 * is not present(i.e. the type of commitment is indicated in the semantics of the message).
 * Otherwise, the electronic signature shall contain a commitment type indication
 * that shall fit one of the commitments types that are mentioned in CommitmentType
 * <pre>
 * SelectedCommitmentTypes ::= SEQUENCE OF CHOICE {
 *   empty NULL,
 *   recognizedCommitmentType {@link CommitmentType}
 * }
 * </pre>
 *
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DERNull
 * @see DERSequence
 */
public class SelectedCommitmentTypes extends ASN1Object {

	private CommitmentType recognizedCommitmentType;

	public CommitmentType getRecognizedCommitmentType() {
		return recognizedCommitmentType;
	}

	public void setRecognizedCommitmentType(CommitmentType recognizedCommitmentType) {
		this.recognizedCommitmentType = recognizedCommitmentType;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		ASN1Primitive object = derSequence.getObjectAt(0).toASN1Primitive();
		if (object instanceof DERNull) {
			this.recognizedCommitmentType = null;
		} else if (object instanceof DERSequence) {
			this.recognizedCommitmentType = new CommitmentType();
			this.recognizedCommitmentType.parse(object);
		}
	}
}
