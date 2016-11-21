package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SignPolExtn extends ASN1Object {

    private ObjectIdentifier extnID;
    private OctetString extnValue;

    public ObjectIdentifier getExtnID() {
        return extnID;
    }

    public void setExtnID(ObjectIdentifier extnID) {
        this.extnID = extnID;
    }

    public OctetString getExtnValue() {
        return extnValue;
    }

    public void setExtnValue(OctetString extnValue) {
        this.extnValue = extnValue;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

        this.extnID = new ObjectIdentifier();
        this.extnID.parse(derSequence.getObjectAt(0).toASN1Primitive());

        this.extnValue = new OctetString();
        this.extnValue.parse(derSequence.getObjectAt(1).toASN1Primitive());
    }

}
