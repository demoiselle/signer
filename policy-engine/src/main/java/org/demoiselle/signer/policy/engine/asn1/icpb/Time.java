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

package org.demoiselle.signer.policy.engine.asn1.icpb;

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERUTCTime;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;

/**
 *
 * Parse {@link ASN1Primitive} and transform {@link ASN1GeneralizedTime} to {@link Date}
 *
 * @see ASN1GeneralizedTime
 * @see ASN1Primitive
 * @see DERUTCTime
 */
public class Time extends ASN1Object {

    private Date time;

    public Date getTime() {
        return time;
    }

    public void setTime(Date generalTime) {
        this.time = generalTime;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        if (derObject instanceof ASN1GeneralizedTime) {
            ASN1GeneralizedTime derGeneralizedTime = (ASN1GeneralizedTime) derObject;
            try {
                this.setTime(derGeneralizedTime.getDate());
            } catch (ParseException ex) {
                this.setTime(null);
            }
        } else if (derObject instanceof DERUTCTime) {
            DERUTCTime derUTCTime = (DERUTCTime) derObject;
            try {
                this.setTime(derUTCTime.getDate());
            } catch (ParseException exception) {
                this.setTime(null);
            }
        }
    }

}
