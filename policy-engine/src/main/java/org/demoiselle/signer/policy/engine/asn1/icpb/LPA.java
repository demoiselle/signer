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

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;

/**
 * V1 definition on:
 *	http://www.iti.gov.br/icp-brasil/repositorio/144-icp-brasil/repositorio/3974-artefatos-de-assinatura-digital
 *
 * 	Collection&lt; @link PolicyInfo &gt; policyInfos;
 * 	{@link Time} nextUpdate;
 *
 */
public class LPA extends ASN1Object {

    private Collection<PolicyInfo> policyInfos;
    private Time nextUpdate;

    private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");

    public Collection<PolicyInfo> getPolicyInfos() {
        return policyInfos;
    }

    public void setPolicyInfos(Collection<PolicyInfo> policyInfos) {
        this.policyInfos = policyInfos;
    }

    public Time getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(Time nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence sequence = ASN1Object.getDERSequence(derObject);
        ASN1Primitive policyInfos = sequence.getObjectAt(0).toASN1Primitive();
        DLSequence policyInfosSequence = (DLSequence) policyInfos;
        if (policyInfosSequence != null && policyInfosSequence.size() > 0) {
            this.policyInfos = new ArrayList<>();
            for (int i = 0; i < policyInfosSequence.size(); i++) {
                PolicyInfo policyInfo = new PolicyInfo();
                policyInfo.parse(policyInfosSequence.getObjectAt(i).toASN1Primitive());
                this.policyInfos.add(policyInfo);
            }
        }
        this.nextUpdate = new Time();
        this.nextUpdate.parse(sequence.getObjectAt(1).toASN1Primitive());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("===================================================").append("\n");
        builder.append(policyMessagesBundle.getString("text.next.update")).append(this.getNextUpdate().getTime()).append("\n");
        builder.append(policyMessagesBundle.getString("text.quantity")).append(this.getPolicyInfos().size()).append("\n");
        builder.append("===================================================").append("\n");
        for (org.demoiselle.signer.policy.engine.asn1.icpb.PolicyInfo policyInfo : this.getPolicyInfos()) {
            builder.append(policyMessagesBundle.getString("text.name")).append(policyInfo.getPolicyName()).append("\n");
            builder.append(policyMessagesBundle.getString("text.uri")).append(policyInfo.getPoliciesURI()).append("\n");
            builder.append(policyMessagesBundle.getString("text.application")).append(policyInfo.getFieldOfApplication()).append("\n");
            builder.append(policyMessagesBundle.getString("text.valid")).append(policyInfo.getSigningPeriod()).append("\n");
            builder.append(policyMessagesBundle.getString("text.status"));
            Time revocationDate = policyInfo.getRevocationDate();
            if (revocationDate != null) {
                builder.append(policyMessagesBundle.getString("text.repealed")).append("\n");
                builder.append(policyMessagesBundle.getString("text.revocation.date")).append(revocationDate != null ? revocationDate.getTime() : policyMessagesBundle.getString("text.revocation.no.date")).append("\n");
            } else {
                builder.append(policyMessagesBundle.getString("text.still.valid")).append("\n");
            }
            builder.append("\t===================================================").append("\n");
        }
        return builder.toString();
    }
}
