package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public enum CertInfoReq {

    none(0), signerOnly(1), fullPath(2);

    private int value;

    private CertInfoReq(int value) {
        this.value = value;
    }

    public static CertInfoReq parse(ASN1Primitive derObject) {
        ASN1Enumerated derEnumerated = ASN1Object.getDEREnumerated(derObject);
        int value = derEnumerated.getValue().intValue();
        for (CertInfoReq certInfoReq : CertInfoReq.values()) {
            if (certInfoReq.value == value) {
                return certInfoReq;
            }
        }
        return null;
    }
}
