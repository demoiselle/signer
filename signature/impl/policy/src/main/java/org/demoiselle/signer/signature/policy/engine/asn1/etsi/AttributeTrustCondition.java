package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class AttributeTrustCondition extends ASN1Object {

    enum TAG {

        attrCertificateTrustTrees(0), attrRevReq(1), attributeConstraints(2);
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

    private Boolean attributeMandated;
    private HowCertAttribute howCertAttribute;
    private CertificateTrustTrees attrCertificateTrustTrees;
    private CertRevReq attrRevReq;
    private AttributeConstraints attributeConstraints;

    public Boolean getAttributeMandated() {
        return attributeMandated;
    }

    public void setAttributeMandated(Boolean attributeMandated) {
        this.attributeMandated = attributeMandated;
    }

    public HowCertAttribute getHowCertAttribute() {
        return howCertAttribute;
    }

    public void setHowCertAttribute(HowCertAttribute howCertAttribute) {
        this.howCertAttribute = howCertAttribute;
    }

    public CertificateTrustTrees getAttrCertificateTrustTrees() {
        return attrCertificateTrustTrees;
    }

    public void setAttrCertificateTrustTrees(
            CertificateTrustTrees attrCertificateTrustTrees) {
        this.attrCertificateTrustTrees = attrCertificateTrustTrees;
    }

    public CertRevReq getAttrRevReq() {
        return attrRevReq;
    }

    public void setAttrRevReq(CertRevReq attrRevReq) {
        this.attrRevReq = attrRevReq;
    }

    public AttributeConstraints getAttributeConstraints() {
        return attributeConstraints;
    }

    public void setAttributeConstraints(AttributeConstraints attributeConstraints) {
        this.attributeConstraints = attributeConstraints;
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
                        case attrCertificateTrustTrees:
                            this.attrCertificateTrustTrees = new CertificateTrustTrees();
                            this.attrCertificateTrustTrees.parse(object);
                            break;
                        case attrRevReq:
                            this.attrRevReq = new CertRevReq();
                            this.attrRevReq.parse(object);
                            break;
                        case attributeConstraints:
                            this.attributeConstraints = new AttributeConstraints();
                            this.attributeConstraints.parse(object);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
        super.parse(derObject);
    }

}
