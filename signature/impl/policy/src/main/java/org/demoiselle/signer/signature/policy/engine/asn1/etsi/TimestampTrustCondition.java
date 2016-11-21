package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class TimestampTrustCondition extends ASN1Object {

    enum TAG {

        ttsCertificateTrustTrees(0), ttsRevReq(1), ttsNameConstraints(2),
        cautionPeriod(3), signatureTimestampDelay(4);
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

    private CertificateTrustTrees ttsCertificateTrustTrees;
    private CertRevReq ttsRevReq;
    private NameConstraints ttsNameConstraints;
    private DeltaTime cautionPeriod;
    private DeltaTime signatureTimestampDelay;

    public CertificateTrustTrees getTtsCertificateTrustTrees() {
        return ttsCertificateTrustTrees;
    }

    public void setTtsCertificateTrustTrees(
            CertificateTrustTrees ttsCertificateTrustTrees) {
        this.ttsCertificateTrustTrees = ttsCertificateTrustTrees;
    }

    public CertRevReq getTtsRevReq() {
        return ttsRevReq;
    }

    public void setTtsRevReq(CertRevReq ttsRevReq) {
        this.ttsRevReq = ttsRevReq;
    }

    public NameConstraints getTtsNameConstraints() {
        return ttsNameConstraints;
    }

    public void setTtsNameConstraints(NameConstraints ttsNameConstraints) {
        this.ttsNameConstraints = ttsNameConstraints;
    }

    public DeltaTime getCautionPeriod() {
        return cautionPeriod;
    }

    public void setCautionPeriod(DeltaTime cautionPeriod) {
        this.cautionPeriod = cautionPeriod;
    }

    public DeltaTime getSignatureTimestampDelay() {
        return signatureTimestampDelay;
    }

    public void setSignatureTimestampDelay(DeltaTime signatureTimestampDelay) {
        this.signatureTimestampDelay = signatureTimestampDelay;
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
                        case ttsCertificateTrustTrees:
                            this.ttsCertificateTrustTrees = new CertificateTrustTrees();
                            this.ttsCertificateTrustTrees.parse(object);
                            break;
                        case ttsRevReq:
                            this.ttsRevReq = new CertRevReq();
                            this.ttsRevReq.parse(object);
                            break;
                        case ttsNameConstraints:
                            this.ttsNameConstraints = new NameConstraints();
                            this.ttsNameConstraints.parse(object);
                            break;
                        case cautionPeriod:
                            this.cautionPeriod = new DeltaTime();
                            this.cautionPeriod.parse(object);
                            break;
                        case signatureTimestampDelay:
                            this.signatureTimestampDelay = new DeltaTime();
                            this.signatureTimestampDelay.parse(object);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

}
