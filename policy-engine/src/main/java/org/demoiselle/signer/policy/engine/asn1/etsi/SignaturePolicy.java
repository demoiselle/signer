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
import org.bouncycastle.asn1.DEROctetString;


public class SignaturePolicy {

    private AlgorithmIdentifier signPolicyHashAlg;
    private SignPolicyInfo signPolicyInfo;
    private SignPolicyHash signPolicyHash;
    private String signPolicyURI;

    public AlgorithmIdentifier getSignPolicyHashAlg() {
        return signPolicyHashAlg;
    }

    public void setSignPolicyHashAlg(AlgorithmIdentifier signPolicyHashAlg) {
        this.signPolicyHashAlg = signPolicyHashAlg;
    }

    public SignPolicyInfo getSignPolicyInfo() {
        return signPolicyInfo;
    }

    public void setSignPolicyInfo(SignPolicyInfo signPolicyInfo) {
        this.signPolicyInfo = signPolicyInfo;
    }

    public SignPolicyHash getSignPolicyHash() {
        return signPolicyHash;
    }

    public void setSignPolicyHash(SignPolicyHash signPolicyHash) {
        this.signPolicyHash = signPolicyHash;
    }

    public String getSignPolicyURI() {
		return signPolicyURI;
	}

	public void setSignPolicyURI(String signPolicyURI) {
		this.signPolicyURI = signPolicyURI;
	}
    
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.signPolicyHashAlg = new AlgorithmIdentifier();
        this.signPolicyHashAlg.parse(derSequence.getObjectAt(0).toASN1Primitive());
        this.signPolicyInfo = new SignPolicyInfo();
        this.signPolicyInfo.parse(derSequence.getObjectAt(1).toASN1Primitive());          
        if (derSequence.size() == 3) {
            this.signPolicyHash = new SignPolicyHash((DEROctetString) derSequence.getObjectAt(2));
        }
    }

    
    
    
    
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Algoritmo Hash da Política.......: ").append(this.getSignPolicyHashAlg().getAlgorithm().getValue()).append("\n");
        builder.append("Hash da Política.................: ").append(this.getSignPolicyHash().getValue()).append("\n");
        builder.append("OID da Política..................: ").append(this.getSignPolicyInfo().getSignPolicyIdentifier().getValue()).append("\n");
        builder.append("Data Lancamento da Política......: ").append(this.getSignPolicyInfo().getDateOfIssue().getDate()).append("\n");
        builder.append("Emissor da Política..............: ").append(this.getSignPolicyInfo().getPolicyIssuerName()).append("\n");
        builder.append("Campo de aplicação da Política...: ").append(this.getSignPolicyInfo().getFieldOfApplication().getValue()).append("\n");
        builder.append("Politica válida entre............: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()).append("\n");
        builder.append("External Signed Data.............: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getExternalSignedData()).append("\n");
        builder.append("MandatedCertificateRef...........: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef()).append("\n");
        builder.append("MandatedCertificateInfo..........: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo()).append("\n");

        for (AlgAndLength oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getAlgorithmConstraintSet().getSignerAlgorithmConstraints().getAlgAndLengths()) {
            builder.append("Algoritmo de assinatura..........: ").append(oi.getAlgID()).append("\n");
            builder.append("Tamanho mínimo da chave..........: ").append(oi.getMinKeyLength()).append("\n");
        }

        builder.append("==============================================================").append("\n");
        for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers()) {
            builder.append("OID de atributos assinados.......: ").append(oi.getValue()).append("\n");
        }

        builder.append("==============================================================").append("\n");

        if (this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
            for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
                builder.append("OID de atributos nao assinados...: ").append(oi.getValue()).append("\n");
            }
        }

        if (this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
            builder.append("==============================================================").append("\n");
            for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
                builder.append("OID de atributos nao assinados...: ").append(oi.getValue()).append("\n");
            }
        }

        return builder.toString();
    }

}
