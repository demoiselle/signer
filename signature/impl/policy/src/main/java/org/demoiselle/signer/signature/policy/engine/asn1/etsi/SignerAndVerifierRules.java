package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SignerAndVerifierRules extends ASN1Object {

    private SignerRules signerRules;
    private VerifierRules verifierRules;

    public SignerRules getSignerRules() {
        return signerRules;
    }

    public void setSignerRules(SignerRules signerRules) {
        this.signerRules = signerRules;
    }

    public VerifierRules getVerifierRules() {
        return verifierRules;
    }

    public void setVerifierRules(VerifierRules verifierRules) {
        this.verifierRules = verifierRules;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);

        this.signerRules = new SignerRules();
        this.signerRules.parse(derSequence.getObjectAt(0).toASN1Primitive());

        this.verifierRules = new VerifierRules();
        this.verifierRules.parse(derSequence.getObjectAt(1).toASN1Primitive());
    }

}
