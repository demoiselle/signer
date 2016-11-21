package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class AcceptablePolicySet extends ASN1Object {

    private Collection<CertPolicyId> certPolicyIds;

    public Collection<CertPolicyId> getCertPolicyIds() {
        return certPolicyIds;
    }

    public void setCertPolicyIds(Collection<CertPolicyId> certPolicyIds) {
        this.certPolicyIds = certPolicyIds;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        int total = derSequence.size();
        for (int i = 0; i < total; i++) {
            CertPolicyId certPolicyId = new CertPolicyId();
            certPolicyId.parse(derSequence.getObjectAt(i).toASN1Primitive());
            if (this.certPolicyIds == null) {
                this.certPolicyIds = new ArrayList<>();
            }
            this.certPolicyIds.add(certPolicyId);
        }
    }

}
