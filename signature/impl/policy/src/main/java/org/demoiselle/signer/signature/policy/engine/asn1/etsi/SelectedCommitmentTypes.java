package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SelectedCommitmentTypes extends ASN1Object {

    private CommitmentType recognizedCommitmentType;

    public CommitmentType getRecognizedCommitmentType() {
        return recognizedCommitmentType;
    }

    public void setRecognizedCommitmentType(CommitmentType recognizedCommitmentType) {
        this.recognizedCommitmentType = recognizedCommitmentType;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        ASN1Primitive object = derSequence.getObjectAt(0).toASN1Primitive();
        if (object instanceof DERNull) {
            this.recognizedCommitmentType = null;
        } else if (object instanceof DERSequence) {
            this.recognizedCommitmentType = new CommitmentType();
            this.recognizedCommitmentType.parse(object);
        }
    }

}
