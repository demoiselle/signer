package org.demoiselle.signer.signature.policy.engine.asn1;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DLSequence;

public abstract class ASN1Object {

    public static ASN1Sequence getDERSequence(ASN1Primitive derObject) {
        ASN1Sequence sequence = null;
        if (derObject instanceof DERTaggedObject) {
            ASN1Primitive object = ((DERTaggedObject) derObject).getObject();
            if (object instanceof DERSequence) {
                sequence = (DERSequence) object;
            }
        } else if (derObject instanceof DERSequence) {
            sequence = (DERSequence) derObject;
        } else if (derObject instanceof DLSequence) {

            sequence = (DLSequence) derObject.toASN1Primitive();
        }
        return sequence;
    }

    public static ASN1Enumerated getDEREnumerated(ASN1Primitive derObject) {
        ASN1Enumerated derEnumerated = null;
        if (derObject instanceof DERTaggedObject) {
            ASN1Primitive object = ((DERTaggedObject) derObject).getObject();
            if (object instanceof ASN1Enumerated) {
                derEnumerated = (ASN1Enumerated) object;
            }
        } else if (derObject instanceof ASN1Enumerated) {
            derEnumerated = (ASN1Enumerated) derObject;
        }
        return derEnumerated;
    }

    public void parse(ASN1Primitive derObject) {
        System.out.println(this.getClass() + " : não implementado");
    }
}
