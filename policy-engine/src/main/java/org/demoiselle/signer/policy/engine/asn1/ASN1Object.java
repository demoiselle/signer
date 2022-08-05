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

package org.demoiselle.signer.policy.engine.asn1;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * Abstract class for provide methods to get {@link DERSequence}
 * and {@link ASN1Enumerated} from {@link ASN1Primitive}.
 *
 * @see ASN1Enumerated
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DERSequence
 * @see DERTaggedObject
 * @see DLSequence
 */
public abstract class ASN1Object {

	private static final MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");

	/**
	 * @param derObject Object to convert from.
	 * @return Corresponding {@link DERSequence} or null, if not possible.
	 * @see ASN1Primitive
	 */
	public static ASN1Sequence getDERSequence(ASN1Primitive derObject) {
		ASN1Sequence sequence = null;
		if (derObject instanceof DERTaggedObject) {
			ASN1Primitive object = ((DERTaggedObject) derObject).getObject();
			if (object instanceof DERSequence) {
				sequence = (DERSequence) object;
			}
		} else if (derObject instanceof DERSequence) {
			sequence = (DERSequence) derObject;
		} else if (derObject instanceof DLSequence) {

			sequence = (DLSequence) derObject.toASN1Primitive();
		}
		return sequence;
	}

	/**
	 * @param derObject Primitive object to convert to Enumerated
	 * @return ASN1 Enumerated ({@link ASN1Enumerated}), or null
	 * if not possible to convert.
	 * @see ASN1Primitive
	 */
	public static ASN1Enumerated getDEREnumerated(ASN1Primitive derObject) {
		ASN1Enumerated derEnumerated = null;
		if (derObject instanceof DERTaggedObject) {
			ASN1Primitive object = ((DERTaggedObject) derObject).getObject();
			if (object instanceof ASN1Enumerated) {
				derEnumerated = (ASN1Enumerated) object;
			}
		} else if (derObject instanceof ASN1Enumerated) {
			derEnumerated = (ASN1Enumerated) derObject;
		}
		return derEnumerated;
	}

	/**
	 * @param derObject ASN1 Primitive to parse
	 */
	public void parse(ASN1Primitive derObject) {
		System.out.println(this.getClass() + policyMessagesBundle.getString("info.not.implemented"));
	}
}
