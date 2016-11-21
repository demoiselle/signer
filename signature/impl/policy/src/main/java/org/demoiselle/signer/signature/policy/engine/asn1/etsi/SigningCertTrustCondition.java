package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SigningCertTrustCondition extends ASN1Object {

    private CertificateTrustTrees signerTrustTrees;
    private CertRevReq signerRevReq;

    public CertificateTrustTrees getSignerTrustTrees() {
        return signerTrustTrees;
    }

    public void setSignerTrustTrees(CertificateTrustTrees signerTrustTrees) {
        this.signerTrustTrees = signerTrustTrees;
    }

    public CertRevReq getSignerRevReq() {
        return signerRevReq;
    }

    public void setSignerRevReq(CertRevReq signerRevReq) {
        this.signerRevReq = signerRevReq;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.signerTrustTrees = new CertificateTrustTrees();
        this.signerTrustTrees.parse(derSequence.getObjectAt(0).toASN1Primitive());
        this.signerRevReq = new CertRevReq();
        this.signerRevReq.parse(derSequence.getObjectAt(1).toASN1Primitive());
    }

}
