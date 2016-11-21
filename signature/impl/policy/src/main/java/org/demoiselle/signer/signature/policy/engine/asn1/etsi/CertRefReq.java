package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public enum CertRefReq {

    signerOnly(1), fullPath(2);

    private int value;

    private CertRefReq(int value) {
        this.value = value;
    }

    public static CertRefReq parse(ASN1Primitive derObject) {
        ASN1Enumerated derEnumerated = ASN1Object.getDEREnumerated(derObject);
        int value = derEnumerated.getValue().intValue();
        for (CertRefReq certRefReq : CertRefReq.values()) {
            if (certRefReq.value == value) {
                return certRefReq;
            }
        }
        return null;
    }

}
