package org.demoiselle.signer.signature.policy.engine.asn1.icpb.v2;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DLSequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.signature.policy.engine.asn1.GeneralizedTime;

public class LPA extends ASN1Object {

    private Version version;
    private Collection<PolicyInfo> policyInfos;
    private GeneralizedTime nextUpdate;

    public Version getVersion() {
        return version;
    }

    public void setVersion(Version version) {
        this.version = version;
    }

    public Collection<PolicyInfo> getPolicyInfos() {
        return policyInfos;
    }

    public void setPolicyInfos(Collection<PolicyInfo> policyInfos) {
        this.policyInfos = policyInfos;
    }

    public GeneralizedTime getNextUpdate() {
        return nextUpdate;
    }

    public void setNextUpdate(GeneralizedTime nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    public void parse(ASN1Primitive derObject) {
        ASN1Sequence sequence = ASN1Object.getDERSequence(derObject);
        ASN1Primitive firstObject = sequence.getObjectAt(0).toASN1Primitive();
        this.version = new Version();
        int indice = 0;
        if (firstObject instanceof ASN1Integer) {
            this.version.parse(firstObject);
            indice++;
        }
        ASN1Primitive policyInfos = sequence.getObjectAt(indice).toASN1Primitive();
        DLSequence policyInfosSequence = (DLSequence) policyInfos;
        if (policyInfosSequence != null && policyInfosSequence.size() > 0) {
            this.policyInfos = new ArrayList<>();
            for (int i = 0; i < policyInfosSequence.size(); i++) {
                PolicyInfo policyInfo = new PolicyInfo();
                policyInfo.parse(policyInfosSequence.getObjectAt(i).toASN1Primitive());
                this.policyInfos.add(policyInfo);
            }
        }
        this.nextUpdate = new GeneralizedTime();
        this.nextUpdate.parse(sequence.getObjectAt(indice + 1).toASN1Primitive());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("===================================================").append("\n");
        builder.append("Próxima Atualização.: ").append(this.getNextUpdate().getDate()).append("\n");
        builder.append("Qtds Políticas......: ").append(this.getPolicyInfos().size()).append("\n");
        builder.append("===================================================");
        for (PolicyInfo policyInfo : this.getPolicyInfos()) {
            builder.append("\tPeríodo de Assinatura: ").append(policyInfo.getSigningPeriod()).append("\n");
            builder.append("\tOID da Política......: ").append(policyInfo.getPolicyOID().getValue()).append("\n");
            builder.append("\tURI da Política......: ").append(policyInfo.getPolicyURI()).append("\n");
            builder.append("\tAlgoritmo Hash.......: ").append(policyInfo.getPolicyDigest().getHashAlgorithm().getAlgorithm().getId()).append("\n");
            builder.append("\tHash.................: ").append(policyInfo.getPolicyDigest().getHashValue().toString()).append("\n");
            builder.append("\tStatus...............: ");
            GeneralizedTime revocationDate = policyInfo.getRevocationDate();
            if (revocationDate != null) {
                builder.append("Esta política está revogada.").append("\n");
                builder.append("\tData de Revogação....: ").append(revocationDate != null ? revocationDate.getDate() : "não há data de revogação").append("\n");
            } else {
                builder.append("Esta política ainda está em vigor.").append("\n");
            }
            builder.append("\t===================================================").append("\n");
        }
        return builder.toString();
    }

}
