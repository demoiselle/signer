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

import java.io.UnsupportedEncodingException;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * To get UTF8 String value of DEROctetString.
 *
 * @see ASN1Primitive
 * @see DEROctetString
 * @see ASN1Object
 * @see org.bouncycastle.asn1.ASN1Object
 * @see MessagesBundle
 */
public class OctetString extends ASN1Object {

	private String value;
	protected DEROctetString derOctetString;

	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

	public String getValueUTF8() {
		String result;
		try {
			result = new String(this.derOctetString.getOctets(), "UTF8");
		} catch (UnsupportedEncodingException error) {
			throw new RuntimeException(policyMessagesBundle.getString("error.convert.octet"), error);
		}
		return result;
	}

	public DEROctetString getDerOctetString() {
		return derOctetString;
	}

	public void setDerOctetString(DEROctetString derOctetString) {
		this.derOctetString = derOctetString;
	}

	@Override
	public void parse(ASN1Primitive derObject) {
		if (derObject instanceof DEROctetString) {
			this.derOctetString = (DEROctetString) derObject;
			String octetString = derOctetString.toString();
			octetString = octetString.substring(1);
			this.setValue(octetString);
		}
	}
}
