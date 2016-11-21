package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

/**
 * AlgAndLength ::= SEQUENCE { algID OBJECT IDENTIFIER, minKeyLength INTEGER
 * OPTIONAL, -- Minimum key length in bits other SignPolExtensions OPTIONAL }
 *
 * @author 09275643784
 *
 */
public class AlgAndLength extends ASN1Object {

    private ObjectIdentifier algID;
    private Integer minKeyLength;
    private SignPolExtensions other;

    public ObjectIdentifier getAlgID() {
        return algID;
    }

    public void setAlgID(ObjectIdentifier algID) {
        this.algID = algID;
    }

    public Integer getMinKeyLength() {
        return minKeyLength;
    }

    public void setMinKeyLength(Integer minKeyLength) {
        this.minKeyLength = minKeyLength;
    }

    public SignPolExtensions getOther() {
        return other;
    }

    public void setOther(SignPolExtensions other) {
        this.other = other;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.algID = new ObjectIdentifier();
        this.algID.parse(derSequence.getObjectAt(0).toASN1Primitive());
        if (derSequence.size() >= 2) {
            ASN1Integer derInteger = (ASN1Integer) derSequence.getObjectAt(1).toASN1Primitive();
            this.setMinKeyLength(derInteger.getValue().intValue());
        }
        if (derSequence.size() == 3) {
            this.other = new SignPolExtensions();
            this.other.parse(derSequence.getObjectAt(2).toASN1Primitive());
        }
    }

}
