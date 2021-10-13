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

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.asn1.etsi.SigningPeriod;

/**
 *
 * V1 definition on:
 *	http://www.iti.gov.br/icp-brasil/repositorio/144-icp-brasil/repositorio/3974-artefatos-de-assinatura-digital
 *
 *    org.bouncycastle.asn1.x500.DirectoryString policyName;
 *    org.bouncycastle.asn1.x500.DirectoryString fieldOfApplication;
 *    {@link SigningPeriod} signingPeriod;
 *    {@link Time} revocationDate;
 *    {@link PoliciesURI} policiesURI;
 *    {@link PoliciesDigest} policiesDigest;
 *
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DERTaggedObject
 * @see DirectoryString
 * @see SigningPeriod
 */
public class PolicyInfo extends ASN1Object {

    private DirectoryString policyName;
    private DirectoryString fieldOfApplication;
    private SigningPeriod signingPeriod;
    private Time revocationDate;
    private PoliciesURI policiesURI;
    private PoliciesDigest policiesDigest;

    public DirectoryString getPolicyName() {
        return policyName;
    }

    public void setPolicyName(DirectoryString policyName) {
        this.policyName = policyName;
    }

    public DirectoryString getFieldOfApplication() {
        return fieldOfApplication;
    }

    public void setFieldOfApplication(DirectoryString fieldOfApplication) {
        this.fieldOfApplication = fieldOfApplication;
    }

    public Time getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Time revocationDate) {
        this.revocationDate = revocationDate;
    }

    public SigningPeriod getSigningPeriod() {
        return signingPeriod;
    }

    public void setSigningPeriod(SigningPeriod signingPeriod) {
        this.signingPeriod = signingPeriod;
    }

    public PoliciesURI getPoliciesURI() {
        return policiesURI;
    }

    public void setPoliciesURI(PoliciesURI policiesURI) {
        this.policiesURI = policiesURI;
    }

    public PoliciesDigest getPoliciesDigest() {
        return policiesDigest;
    }

    public void setPoliciesDigest(PoliciesDigest policiesDigest) {
        this.policiesDigest = policiesDigest;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        ASN1Primitive firstObject = derSequence.getObjectAt(0).toASN1Primitive();
        this.policyName = new DirectoryString(firstObject.toString());
        ASN1Primitive secondObject = derSequence.getObjectAt(1).toASN1Primitive();
        String fieldOfApplication = secondObject.toString();
        this.fieldOfApplication = new DirectoryString(fieldOfApplication);
        this.signingPeriod = new SigningPeriod();
        this.signingPeriod.parse(derSequence.getObjectAt(2).toASN1Primitive());

        int indice = 3;
        ASN1Primitive revocationObject = derSequence.getObjectAt(indice).toASN1Primitive();
        if (!(secondObject instanceof DERTaggedObject)) {
            indice = 4;
        }
        if (indice == 3) {
            this.revocationDate = new Time();
            this.revocationDate.parse(revocationObject);
        }
    }
}
