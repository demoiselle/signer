package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class RevReq extends ASN1Object {

    private EnuRevReq enuRevReq;
    private SignPolExtensions exRevReq;

    public EnuRevReq getEnuRevReq() {
        return enuRevReq;
    }

    public void setEnuRevReq(EnuRevReq enuRevReq) {
        this.enuRevReq = enuRevReq;
    }

    public SignPolExtensions getExRevReq() {
        return exRevReq;
    }

    public void setExRevReq(SignPolExtensions exRevReq) {
        this.exRevReq = exRevReq;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.enuRevReq = EnuRevReq.parse(derSequence.getObjectAt(0).toASN1Primitive());

        if (derSequence.size() == 2) {
            this.exRevReq = new SignPolExtensions();
            this.exRevReq.parse(derSequence.getObjectAt(1).toASN1Primitive());
        }

    }

}
