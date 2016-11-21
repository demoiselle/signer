package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.signature.policy.engine.asn1.GeneralizedTime;

public class SignPolicyInfo extends ASN1Object {

    private SignPolicyId signPolicyIdentifier;
    private GeneralizedTime dateOfIssue;
    private PolicyIssuerName policyIssuerName;
    private FieldOfApplication fieldOfApplication;
    private SignatureValidationPolicy signatureValidationPolicy;
    private SignPolExtensions signPolExtensions;

    public SignPolicyId getSignPolicyIdentifier() {
        return signPolicyIdentifier;
    }

    public void setSignPolicyIdentifier(SignPolicyId signPolicyIdentifier) {
        this.signPolicyIdentifier = signPolicyIdentifier;
    }

    public GeneralizedTime getDateOfIssue() {
        return dateOfIssue;
    }

    public void setDateOfIssue(GeneralizedTime dateOfIssue) {
        this.dateOfIssue = dateOfIssue;
    }

    public PolicyIssuerName getPolicyIssuerName() {
        return policyIssuerName;
    }

    public void setPolicyIssuerName(PolicyIssuerName policyIssuerName) {
        this.policyIssuerName = policyIssuerName;
    }

    public FieldOfApplication getFieldOfApplication() {
        return fieldOfApplication;
    }

    public void setFieldOfApplication(FieldOfApplication fieldOfApplication) {
        this.fieldOfApplication = fieldOfApplication;
    }

    public SignatureValidationPolicy getSignatureValidationPolicy() {
        return signatureValidationPolicy;
    }

    public void setSignatureValidationPolicy(
            SignatureValidationPolicy signatureValidationPolicy) {
        this.signatureValidationPolicy = signatureValidationPolicy;
    }

    public SignPolExtensions getSignPolExtensions() {
        return signPolExtensions;
    }

    public void setSignPolExtensions(SignPolExtensions signPolExtensions) {
        this.signPolExtensions = signPolExtensions;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.signPolicyIdentifier = new SignPolicyId();
        this.signPolicyIdentifier.parse(derSequence.getObjectAt(0).toASN1Primitive());

        this.dateOfIssue = new GeneralizedTime();
        this.dateOfIssue.parse(derSequence.getObjectAt(1).toASN1Primitive());

        this.policyIssuerName = new PolicyIssuerName();
        this.policyIssuerName.parse(derSequence.getObjectAt(2).toASN1Primitive());

        this.fieldOfApplication = new FieldOfApplication();
        this.fieldOfApplication.parse(derSequence.getObjectAt(3).toASN1Primitive());

        this.signatureValidationPolicy = new SignatureValidationPolicy();
        this.signatureValidationPolicy.parse(derSequence.getObjectAt(4).toASN1Primitive());

        if (derSequence.size() == 6) {
            this.signPolExtensions = new SignPolExtensions();
            this.signPolExtensions.parse(derSequence.getObjectAt(5).toASN1Primitive());
        }

    }

}
