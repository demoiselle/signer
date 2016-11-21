package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class PolicyConstraints extends ASN1Object {

    enum TAG {

        requireExplicitPolicy(0), inhibitPolicyMapping(1);
        int value;

        private TAG(int value) {
            this.value = value;
        }

        public static TAG getTag(int value) {
            for (TAG tag : TAG.values()) {
                if (tag.value == value) {
                    return tag;
                }
            }
            return null;
        }
    }

    private SkipCerts requireExplicitPolicy;
    private SkipCerts inhibitPolicyMapping;

    public SkipCerts getRequireExplicitPolicy() {
        return requireExplicitPolicy;
    }

    public void setRequireExplicitPolicy(SkipCerts requireExplicitPolicy) {
        this.requireExplicitPolicy = requireExplicitPolicy;
    }

    public SkipCerts getInhibitPolicyMapping() {
        return inhibitPolicyMapping;
    }

    public void setInhibitPolicyMapping(SkipCerts inhibitPolicyMapping) {
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        int total = derSequence.size();

        if (total > 0) {
            for (int i = 0; i < total; i++) {
                ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
                if (object instanceof DERTaggedObject) {
                    DERTaggedObject derTaggedObject = (DERTaggedObject) object;
                    TAG tag = TAG.getTag(derTaggedObject.getTagNo());
                    switch (tag) {
                        case requireExplicitPolicy:
                            this.requireExplicitPolicy = new SkipCerts();
                            this.requireExplicitPolicy.parse(object);
                            break;
                        case inhibitPolicyMapping:
                            this.inhibitPolicyMapping = new SkipCerts();
                            this.inhibitPolicyMapping.parse(object);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

}
