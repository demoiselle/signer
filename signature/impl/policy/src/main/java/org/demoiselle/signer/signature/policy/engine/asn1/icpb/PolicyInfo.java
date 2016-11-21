package org.demoiselle.signer.signature.policy.engine.asn1.icpb;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.signature.policy.engine.asn1.etsi.SigningPeriod;

public class PolicyInfo extends ASN1Object {

    private DirectoryString policyName;
    private DirectoryString fieldOfApplication;
    private SigningPeriod signingPeriod;
    private Time revocationDate;
    private PoliciesURI policiesURI;
    private PoliciesDigest policiesDigest;

    public DirectoryString getPolicyName() {
        return policyName;
    }

    public void setPolicyName(DirectoryString policyName) {
        this.policyName = policyName;
    }

    public DirectoryString getFieldOfApplication() {
        return fieldOfApplication;
    }

    public void setFieldOfApplication(DirectoryString fieldOfApplication) {
        this.fieldOfApplication = fieldOfApplication;
    }

    public Time getRevocationDate() {
        return revocationDate;
    }

    public void setRevocationDate(Time revocationDate) {
        this.revocationDate = revocationDate;
    }

    public SigningPeriod getSigningPeriod() {
        return signingPeriod;
    }

    public void setSigningPeriod(SigningPeriod signingPeriod) {
        this.signingPeriod = signingPeriod;
    }

    public PoliciesURI getPoliciesURI() {
        return policiesURI;
    }

    public void setPoliciesURI(PoliciesURI policiesURI) {
        this.policiesURI = policiesURI;
    }

    public PoliciesDigest getPoliciesDigest() {
        return policiesDigest;
    }

    public void setPoliciesDigest(PoliciesDigest policiesDigest) {
        this.policiesDigest = policiesDigest;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        ASN1Primitive firstObject = derSequence.getObjectAt(0).toASN1Primitive();
        this.policyName = new DirectoryString(firstObject.toString());
        ASN1Primitive secondObject = derSequence.getObjectAt(1).toASN1Primitive();
        String fieldOfApplication = secondObject.toString();
        this.fieldOfApplication = new DirectoryString(fieldOfApplication);
        this.signingPeriod = new SigningPeriod();
        this.signingPeriod.parse(derSequence.getObjectAt(2).toASN1Primitive());

        int indice = 3;
        ASN1Primitive revocationObject = derSequence.getObjectAt(indice).toASN1Primitive();
        if (!(secondObject instanceof DERTaggedObject)) {
            indice = 4;
        }
        if (indice == 3) {
            this.revocationDate = new Time();
            this.revocationDate.parse(revocationObject);
        }
    }

}
