package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import java.util.ArrayList;
import java.util.Collection;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class AlgorithmConstraints extends ASN1Object {

    private Collection<AlgAndLength> algAndLengths;

    public Collection<AlgAndLength> getAlgAndLengths() {
        return algAndLengths;
    }

    public void setAlgAndLengths(Collection<AlgAndLength> algAndLengths) {
        this.algAndLengths = algAndLengths;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        int total = derSequence.size();
        for (int i = 0; i < total; i++) {
            AlgAndLength algAndLength = new AlgAndLength();
            algAndLength.parse(derSequence.getObjectAt(i).toASN1Primitive());
            if (this.algAndLengths == null) {
                this.algAndLengths = new ArrayList<AlgAndLength>();
            }
            this.algAndLengths.add(algAndLength);
        }
    }

}
