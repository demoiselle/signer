package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class CommitmentType extends ASN1Object {

    enum TAG {

        fieldOfApplication(0), semantics(1);
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

    private CommitmentTypeIdentifier identifier;
    private FieldOfApplication fieldOfApplication;
    private String semantics;

    public CommitmentTypeIdentifier getIdentifier() {
        return identifier;
    }

    public void setIdentifier(CommitmentTypeIdentifier identifier) {
        this.identifier = identifier;
    }

    public FieldOfApplication getFieldOfApplication() {
        return fieldOfApplication;
    }

    public void setFieldOfApplication(FieldOfApplication fieldOfApplication) {
        this.fieldOfApplication = fieldOfApplication;
    }

    public String getSemantics() {
        return semantics;
    }

    public void setSemantics(String semantics) {
        this.semantics = semantics;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

        this.identifier = new CommitmentTypeIdentifier();
        this.identifier.parse(derSequence.getObjectAt(0).toASN1Primitive());

        int total = derSequence.size();

        if (total > 0) {
            for (int i = 0; i < total; i++) {
                ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
                if (object instanceof DERTaggedObject) {
                    DERTaggedObject derTaggedObject = (DERTaggedObject) object;
                    TAG tag = TAG.getTag(derTaggedObject.getTagNo());
                    switch (tag) {
                        case fieldOfApplication:
                            this.fieldOfApplication = new FieldOfApplication();
                            this.fieldOfApplication.parse(object);
                            break;
                        case semantics:
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

}
