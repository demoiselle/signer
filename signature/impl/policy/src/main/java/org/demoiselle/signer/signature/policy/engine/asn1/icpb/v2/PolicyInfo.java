package org.demoiselle.signer.signature.policy.engine.asn1.icpb.v2;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.signature.policy.engine.asn1.GeneralizedTime;
import org.demoiselle.signer.signature.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.signature.policy.engine.asn1.etsi.SigningPeriod;

public class PolicyInfo extends ASN1Object {

    private SigningPeriod signingPeriod;
    private GeneralizedTime revocationDate;
    private ObjectIdentifier policyOID;
    private String policyURI;
    private OtherHashAlgAndValue policyDigest;

    public SigningPeriod getSigningPeriod() {
        return signingPeriod;
    }

    public void setSigningPeriod(SigningPeriod signingPeriod) {
        this.signingPeriod = signingPeriod;
    }

    public GeneralizedTime getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(GeneralizedTime revocationDate) {
        this.revocationDate = revocationDate;
    }

    public ObjectIdentifier getPolicyOID() {
        return policyOID;
    }

    public void setPolicyOID(ObjectIdentifier policyOID) {
        this.policyOID = policyOID;
    }

    public String getPolicyURI() {
        return policyURI;
    }

    public void setPolicyURI(String policyURI) {
        this.policyURI = policyURI;
    }

    public OtherHashAlgAndValue getPolicyDigest() {
        return policyDigest;
    }

    public void setPolicyDigest(OtherHashAlgAndValue policyDigest) {
        this.policyDigest = policyDigest;
    }

    @Override
    public void parse(ASN1Primitive primitive) {
        ASN1Sequence sequence1 = ASN1Object.getDERSequence(primitive);
        this.signingPeriod = new SigningPeriod();
        this.signingPeriod.parse(sequence1.getObjectAt(0).toASN1Primitive());
        int indice = 2;

        ASN1Primitive secondObject = sequence1.getObjectAt(1).toASN1Primitive();
        if (secondObject instanceof ASN1ObjectIdentifier) {
            indice = 1;
        }
        if (indice == 2) {
            this.revocationDate = new GeneralizedTime();
            this.revocationDate.parse(secondObject);
        }
        this.policyOID = new ObjectIdentifier();
        this.policyOID.parse(sequence1.getObjectAt(indice).toASN1Primitive());
        DERIA5String policyURI = (DERIA5String) sequence1.getObjectAt(indice + 1);
        this.policyURI = policyURI.getString();

        ASN1Primitive policyDigest = sequence1.getObjectAt(indice + 2).toASN1Primitive();
        ASN1Sequence sequence2 = ASN1Sequence.getInstance(policyDigest);

        DEROctetString derOctetString = (DEROctetString) sequence2.getObjectAt(1).toASN1Primitive();
        ASN1Sequence sequence3 = ASN1Object.getDERSequence(sequence2.getObjectAt(0).toASN1Primitive());
        ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) sequence3.getObjectAt(0).toASN1Primitive();
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(objectIdentifier);
        this.policyDigest = new OtherHashAlgAndValue(algorithmIdentifier, derOctetString);
    }

}
