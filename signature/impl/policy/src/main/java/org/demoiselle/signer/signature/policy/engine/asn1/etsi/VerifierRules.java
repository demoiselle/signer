package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class VerifierRules extends ASN1Object {

    private MandatedUnsignedAttr mandatedUnsignedAttr;
    private SignPolExtensions signPolExtensions;

    public MandatedUnsignedAttr getMandatedUnsignedAttr() {
        return mandatedUnsignedAttr;
    }

    public void setMandatedUnsignedAttr(MandatedUnsignedAttr mandatedUnsignedAttr) {
        this.mandatedUnsignedAttr = mandatedUnsignedAttr;
    }

    public SignPolExtensions getSignPolExtensions() {
        return signPolExtensions;
    }

    public void setSignPolExtensions(SignPolExtensions signPolExtensions) {
        this.signPolExtensions = signPolExtensions;
    }

    @Override
    public void parse(ASN1Primitive derObject) {

        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

        this.mandatedUnsignedAttr = new MandatedUnsignedAttr();
        this.mandatedUnsignedAttr.parse(derSequence.getObjectAt(0).toASN1Primitive());

        if (derSequence.size() == 2) {
            this.signPolExtensions = new SignPolExtensions();
            this.signPolExtensions.parse(derSequence.getObjectAt(1).toASN1Primitive());
        }
    }

}
