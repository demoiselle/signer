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

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * <pre>
 * CMSAttrs ::= SEQUENCE OF OBJECT IDENTIFIER ObjectIdentifier
 *     mandatedSignedAttr CMSAttrs, -- Mandated CMS signed attributes
 *     mandatedUnsignedAttr CMSAttrs, -- Mandated CMS unsigned attributed
 * </pre>
 *
 * @see ASN1Object
 * @see ObjectIdentifier
 * @see ASN1Primitive
 * @see DERSequence
 */
public class CMSAttrs extends ASN1Object {

	private Collection<ObjectIdentifier> objectIdentifiers;

	public Collection<ObjectIdentifier> getObjectIdentifiers() {
		return objectIdentifiers;
	}

	public void setObjectIdentifiers(Collection<ObjectIdentifier> objectIdentifiers) {
		this.objectIdentifiers = objectIdentifiers;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		DERSequence derSequence = (DERSequence) derObject;
		int total = derSequence.size();
		for (int i = 0; i < total; i++) {
			ObjectIdentifier objectIdentifier = new ObjectIdentifier();
			objectIdentifier.parse(derSequence.getObjectAt(i).toASN1Primitive());
			if (this.objectIdentifiers == null) {
				this.objectIdentifiers = new ArrayList<>();
			}
			this.objectIdentifiers.add(objectIdentifier);
		}
	}

}
