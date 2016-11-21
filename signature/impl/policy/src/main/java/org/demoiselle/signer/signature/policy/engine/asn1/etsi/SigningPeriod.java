package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.signature.policy.engine.asn1.GeneralizedTime;

public class SigningPeriod extends ASN1Object {

    private GeneralizedTime notBefore;
    private GeneralizedTime notAfter;

    public GeneralizedTime getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(GeneralizedTime notBefore) {
        this.notBefore = notBefore;
    }

    public GeneralizedTime getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(GeneralizedTime notAfter) {
        this.notAfter = notAfter;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

        this.notBefore = new GeneralizedTime();
        this.notBefore.parse(derSequence.getObjectAt(0).toASN1Primitive());

        if (derSequence.size() == 2) {
            this.notAfter = new GeneralizedTime();
            this.notAfter.parse(derSequence.getObjectAt(1).toASN1Primitive());
        }
    }

    @Override
    public String toString() {
        return this.notBefore.getDate() + " - " + (this.getNotAfter() != null ? this.getNotAfter().getDate() : "");
    }

}
