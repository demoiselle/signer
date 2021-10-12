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

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 * EnuRevReq ::= ENUMERATED {
 * <p>
 * clrCheck (0), --Checks shall be made against current CRLs (or authority revocation lists)
 * ocspCheck (1), -- The revocation status shall be checked
 * using the Online Certificate Status Protocol (RFC 2450)
 * bothCheck (2), -- Both CRL and OCSP checks shall be carried out
 * eitherCheck (3), -- At least one of CRL or OCSP checks shall be carried out
 * noCheck (4), -- no check is mandated
 * other (5) -- Other mechanism as defined by signature policy extension }
 *
 * @see ASN1Enumerated
 * @see ASN1Primitive
 */
public enum EnuRevReq {

	clrCheck(0),
	ocspCheck(1),
	bothCheck(2),
	eitherCheck(3),
	noCheck(4),
	other(5);

	private int value;

	EnuRevReq(int value) {
		this.value = value;
	}

	public static EnuRevReq parse(ASN1Primitive derObject) {
		ASN1Enumerated derEnumerated = ASN1Object.getDEREnumerated(derObject);
		int value = derEnumerated.getValue().intValue();
		for (EnuRevReq enuRevReq : EnuRevReq.values()) {
			if (enuRevReq.value == value) {
				return enuRevReq;
			}
		}
		return null;
	}

}
