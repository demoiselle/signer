package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class CMSAttrs extends ASN1Object {

    private Collection<ObjectIdentifier> objectIdentifiers;

    public Collection<ObjectIdentifier> getObjectIdentifiers() {
        return objectIdentifiers;
    }

    public void setObjectIdentifiers(Collection<ObjectIdentifier> objectIdentifiers) {
        this.objectIdentifiers = objectIdentifiers;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        DERSequence derSequence = (DERSequence) derObject;
        int total = derSequence.size();
        for (int i = 0; i < total; i++) {
            ObjectIdentifier objectIdentifier = new ObjectIdentifier();
            objectIdentifier.parse(derSequence.getObjectAt(i).toASN1Primitive());
            if (this.objectIdentifiers == null) {
                this.objectIdentifiers = new ArrayList<ObjectIdentifier>();
            }
            this.objectIdentifiers.add(objectIdentifier);
        }
    }

}
