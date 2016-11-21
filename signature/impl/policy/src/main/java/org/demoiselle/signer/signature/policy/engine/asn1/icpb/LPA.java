package org.demoiselle.signer.signature.policy.engine.asn1.icpb;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class LPA extends ASN1Object {

    private Collection<PolicyInfo> policyInfos;
    private Time nextUpdate;

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
        builder.append("Próxima Atualização.: ").append(this.getNextUpdate().getTime()).append("\n");
        builder.append("Qtds Políticas......: ").append(this.getPolicyInfos().size()).append("\n");
        builder.append("===================================================").append("\n");
        for (org.demoiselle.signer.signature.policy.engine.asn1.icpb.PolicyInfo policyInfo : this.getPolicyInfos()) {
            builder.append("\tPolítica.............: ").append(policyInfo.getPolicyName()).append("\n");
            builder.append("\tURI..................: ").append(policyInfo.getPoliciesURI()).append("\n");
            builder.append("\tAplicação............: ").append(policyInfo.getFieldOfApplication()).append("\n");
            builder.append("\tPeríodo de Assinatura: ").append(policyInfo.getSigningPeriod()).append("\n");
            builder.append("\tStatus...............: ");
            Time revocationDate = policyInfo.getRevocationDate();
            if (revocationDate != null) {
                builder.append("Esta política está revogada.").append("\n");
                builder.append("\tData de Revogação....: ").append(revocationDate != null ? revocationDate.getTime() : "não há data de revogação").append("\n");
            } else {
                builder.append("Esta política ainda está em vigor.").append("\n");
            }
            builder.append("\t===================================================").append("\n");
        }
        return builder.toString();
    }
}
