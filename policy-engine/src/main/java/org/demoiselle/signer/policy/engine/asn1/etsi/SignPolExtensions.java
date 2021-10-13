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
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * ETSI TR 102 272 V1.1.1 (2003-12)
 *
 * <p>Additional signature policy rules may be added to:</p>
 *
 * <ul>
 * <li>the overall signature policy structure, as defined in clause 6.1;</li>
 * <li>the signature validation policy structure, as defined in clause 6.2;</li>
 * <li>the common rules, as defined in clause 6.3;</li>
 * <li>the commitment rules, as defined in clause 6.4;</li>
 * <li>the signer rules, as defined in clause 6.5.1;</li>
 * <li>the verifier rules, as defined in clause 6.5.2;</li>
 * <li>the revocation requirements in clause 6.6.2;</li>
 * <li>the algorithm constraints in clause 6.10.</li>
 * </ul>
 *
 * <p>These extensions to the signature policy rules shall be defined using
 * an ASN.1 syntax with an associated object identifier carried in the
 * SignPolExtn as defined below:</p>
 *
 * <pre>
 * SignPolExtensions ::= SEQUENCE OF {@link SignPolExtn}
 * </pre>
 *
 * @see ASN1Sequence
 * @see ASN1Primitive
 */
public class SignPolExtensions extends ASN1Object {

	private Collection<SignPolExtn> extensions;

	public Collection<SignPolExtn> getExtensions() {
		return extensions;
	}

	public void setExtensions(Collection<SignPolExtn> extensions) {
		this.extensions = extensions;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		int total = derSequence.size();
		for (int i = 0; i < total; i++) {
			SignPolExtn signPolExtn = new SignPolExtn();
			signPolExtn.parse(derSequence.getObjectAt(i).toASN1Primitive());
			if (this.extensions == null) {
				this.extensions = new ArrayList<>();
			}
			this.extensions.add(signPolExtn);
		}
	}

}
