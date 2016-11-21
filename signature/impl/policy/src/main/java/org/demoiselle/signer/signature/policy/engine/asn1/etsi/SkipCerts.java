package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import java.util.Collection;

import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SkipCerts extends ASN1Object {

    private Collection<Integer> skipCerts;

    public Collection<Integer> getSkipCerts() {
        return skipCerts;
    }

    public void setSkipCerts(Collection<Integer> skipCerts) {
        this.skipCerts = skipCerts;
    }

}
