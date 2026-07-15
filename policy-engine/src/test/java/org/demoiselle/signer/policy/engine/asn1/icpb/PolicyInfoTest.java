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

import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.Assert;
import org.junit.Test;

public class PolicyInfoTest {

    @Test
    public void parse_shouldReadRevocationDateWhenTaggedAtIndex3() throws Exception {
        Date now = new Date();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERUTF8String("AD-RB_CAdES"));
        vector.add(new DERUTF8String("Documento de texto"));

        ASN1EncodableVector signingPeriodVector = new ASN1EncodableVector();
        signingPeriodVector.add(new ASN1GeneralizedTime(now));
        vector.add(new DERSequence(signingPeriodVector));

        // revocationDate no índice 3 como ASN1TaggedObject contendo GeneralizedTime
        vector.add(new DERTaggedObject(0, new ASN1GeneralizedTime(now)));

        ASN1Primitive derObject = new DERSequence(vector).toASN1Primitive();

        PolicyInfo policyInfo = new PolicyInfo();
        policyInfo.parse(derObject);

        Assert.assertNotNull("revocationDate deve ser lido quando tagged no índice 3",
                policyInfo.getRevocationDate());
        Assert.assertNotNull("time interno deve estar preenchido",
                policyInfo.getRevocationDate().getTime());
    }

    @Test
    public void parse_shouldNotReadRevocationDateWhenNonTaggedAtIndex3() throws Exception {
        Date now = new Date();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERUTF8String("Politica de Teste"));
        vector.add(new DERUTF8String("Campo de Aplicacao"));

        ASN1EncodableVector signingPeriodVector = new ASN1EncodableVector();
        signingPeriodVector.add(new ASN1GeneralizedTime(now));
        vector.add(new DERSequence(signingPeriodVector));

        // Índice 3 NÃO é tagged (simula revocationDate ausente, próximo campo direto)
        vector.add(new DERUTF8String("http://politica.iti.gov.br/teste"));

        ASN1Primitive derObject = new DERSequence(vector).toASN1Primitive();

        PolicyInfo policyInfo = new PolicyInfo();
        policyInfo.parse(derObject);

        Assert.assertNull("revocationDate deve ser null quando índice 3 não é tagged",
                policyInfo.getRevocationDate());
    }

    @Test
    public void parse_shouldPopulateAllFields() throws Exception {
        Date now = new Date();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERUTF8String("AD-RB_CAdES"));
        vector.add(new DERUTF8String("Documento de texto"));

        ASN1EncodableVector signingPeriodVector = new ASN1EncodableVector();
        signingPeriodVector.add(new ASN1GeneralizedTime(now));
        vector.add(new DERSequence(signingPeriodVector));

        vector.add(new DERTaggedObject(0, new ASN1GeneralizedTime(now)));

        ASN1Primitive derObject = new DERSequence(vector).toASN1Primitive();

        PolicyInfo policyInfo = new PolicyInfo();
        policyInfo.parse(derObject);

        Assert.assertEquals("AD-RB_CAdES", policyInfo.getPolicyName().toString());
        Assert.assertEquals("Documento de texto", policyInfo.getFieldOfApplication().toString());
        Assert.assertNotNull("signingPeriod deve estar preenchido", policyInfo.getSigningPeriod());
        Assert.assertNotNull("revocationDate deve estar preenchido", policyInfo.getRevocationDate());
    }
}
