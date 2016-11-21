package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public enum HowCertAttribute {

    claimedAttribute(0),
    certifiedAttribtes(1),
    either(2);

    private int value;

    private HowCertAttribute(int value) {
        this.value = value;
    }

    public static HowCertAttribute parse(ASN1Primitive derObject) {
        ASN1Enumerated derEnumerated = ASN1Object.getDEREnumerated(derObject);
        int value = derEnumerated.getValue().intValue();
        for (HowCertAttribute howCertAttribute : HowCertAttribute.values()) {
            if (howCertAttribute.value == value) {
                return howCertAttribute;
            }
        }
        return null;
    }

}
