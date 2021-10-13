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

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * Parse an org.bouncycastle.asn1.ASN1GeneralizedTime
 * to get it in java.util.Date format.
 *
 * <p>A GeneralizedTime is a time format in the ASN.1 notation.
 * It consists of a string value representing the calendar date,
 * as defined in ISO 8601, a time of day with an optional
 * fractional seconds element and the optional local
 * time differential factor as defined in ISO 8601.</p>
 *
 * <p>In contrast to the UTCTime class of ASN.1 the GeneralizedTime
 * uses a four-digit representation of the year to avoid possible
 * ambiguity. Another difference is the possibility to encode time
 * information of any wanted precision via the fractional seconds
 * element.</p>
 *
 * @see ASN1GeneralizedTime
 * @see ASN1Primitive
 */
public class GeneralizedTime extends ASN1Object {

	private Date date;

	@Override
	public void parse(ASN1Primitive derObject) {
		if (derObject instanceof ASN1GeneralizedTime) {
			ASN1GeneralizedTime derGeneralizedTime = (ASN1GeneralizedTime) derObject;
			try {
				this.setDate(derGeneralizedTime.getDate());
			} catch (ParseException error) {
				throw new RuntimeException(error);
			}
		}
	}

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}
}
