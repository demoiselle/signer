package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class CertRevReq extends ASN1Object {

    private RevReq endCertRevReq;
    private RevReq caCerts;

    public RevReq getEndCertRevReq() {
        return endCertRevReq;
    }

    public void setEndCertRevReq(RevReq endCertRevReq) {
        this.endCertRevReq = endCertRevReq;
    }

    public RevReq getCaCerts() {
        return caCerts;
    }

    public void setCaCerts(RevReq caCerts) {
        this.caCerts = caCerts;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

        this.endCertRevReq = new RevReq();
        this.endCertRevReq.parse(derSequence.getObjectAt(0).toASN1Primitive());

        this.caCerts = new RevReq();
        this.caCerts.parse(derSequence.getObjectAt(1).toASN1Primitive());
    }

}
