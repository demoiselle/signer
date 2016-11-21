package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SignPolExtensions extends ASN1Object {

    private Collection<SignPolExtn> extensions;

    public Collection<SignPolExtn> getExtensions() {
        return extensions;
    }

    public void setExtensions(Collection<SignPolExtn> extensions) {
        this.extensions = extensions;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        int total = derSequence.size();
        for (int i = 0; i < total; i++) {
            SignPolExtn signPolExtn = new SignPolExtn();
            signPolExtn.parse(derSequence.getObjectAt(i).toASN1Primitive());
            if (this.extensions == null) {
                this.extensions = new ArrayList<>();
            }
            this.extensions.add(signPolExtn);
        }
    }

}
