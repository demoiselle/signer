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
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * <pre>
 * SignPolExtn ::= SEQUENCE {
 * 				extnID OBJECT IDENTIFIER {@link ObjectIdentifier},
 * 				extnValue OCTET STRING {@link OctetString}
 *    }
 * </pre>
 *
 * <p>The extnID field shall contain the object identifier for the extension.
 * The extnValue field shall contain the DER(see ITU-T Recommendation X.690 [3])
 * encoded value of the extension. The definition of an extension, as identified by
 * extnID shall include a definition of the syntax and semantics of the extension.</p>
 *
 * @see ASN1Sequence
 * @see ASN1Primitive
 */
public class SignPolExtn extends ASN1Object {

	private ObjectIdentifier extnID;
	private OctetString extnValue;

	public ObjectIdentifier getExtnID() {
		return extnID;
	}

	public void setExtnID(ObjectIdentifier extnID) {
		this.extnID = extnID;
	}

	public OctetString getExtnValue() {
		return extnValue;
	}

	public void setExtnValue(OctetString extnValue) {
		this.extnValue = extnValue;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

		this.extnID = new ObjectIdentifier();
		this.extnID.parse(derSequence.getObjectAt(0).toASN1Primitive());

		this.extnValue = new OctetString();
		this.extnValue.parse(derSequence.getObjectAt(1).toASN1Primitive());
	}
}
