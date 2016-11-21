package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class ObjectIdentifier extends ASN1Object {

    private String value;

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1ObjectIdentifier derObjectIdentifier = (ASN1ObjectIdentifier) (derObject);
        this.setValue(derObjectIdentifier.getId());
    }

    @Override
    public String toString() {
        return this.value;
    }

}
