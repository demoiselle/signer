package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

/**
 * The CommonRules define rules that are common to all commitment types. These
 * rules are defined in terms of trust conditions for certificates, timestamps
 * and attributes, along with any constraints on attributes that may be included
 * in the electronic signature.
 *
 * @author 07721825741
 */
public class CommonRules extends ASN1Object {

    private SignerAndVerifierRules signerAndVeriferRules;
    private SigningCertTrustCondition signingCertTrustCondition;
    private TimestampTrustCondition timeStampTrustCondition;
    private AttributeTrustCondition attributeTrustCondition;
    private AlgorithmConstraintSet algorithmConstraintSet;
    private SignPolExtensions signPolExtensions;

    public SignerAndVerifierRules getSignerAndVeriferRules() {
        return signerAndVeriferRules;
    }

    public void setSignerAndVeriferRules(
            SignerAndVerifierRules signerAndVeriferRules) {
        this.signerAndVeriferRules = signerAndVeriferRules;
    }

    public SigningCertTrustCondition getSigningCertTrustCondition() {
        return signingCertTrustCondition;
    }

    public void setSigningCertTrustCondition(
            SigningCertTrustCondition signingCertTrustCondition) {
        this.signingCertTrustCondition = signingCertTrustCondition;
    }

    public TimestampTrustCondition getTimeStampTrustCondition() {
        return timeStampTrustCondition;
    }

    public void setTimeStampTrustCondition(
            TimestampTrustCondition timeStampTrustCondition) {
        this.timeStampTrustCondition = timeStampTrustCondition;
    }

    public AttributeTrustCondition getAttributeTrustCondition() {
        return attributeTrustCondition;
    }

    public void setAttributeTrustCondition(
            AttributeTrustCondition attributeTrustCondition) {
        this.attributeTrustCondition = attributeTrustCondition;
    }

    public AlgorithmConstraintSet getAlgorithmConstraintSet() {
        return algorithmConstraintSet;
    }

    public void setAlgorithmConstraintSet(
            AlgorithmConstraintSet algorithmConstraintSet) {
        this.algorithmConstraintSet = algorithmConstraintSet;
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
        int total = derSequence.size();

        if (total > 0) {
            for (int i = 0; i < total; i++) {
                ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
                if (object instanceof DERTaggedObject) {
                    DERTaggedObject derTaggedObject = (DERTaggedObject) object;
                    TAG tag = TAG.getTag(derTaggedObject.getTagNo());
                    switch (tag) {
                        case signerAndVeriferRules:
                            this.signerAndVeriferRules = new SignerAndVerifierRules();
                            this.signerAndVeriferRules.parse(object);
                            break;
                        case signingCertTrustCondition:
                            this.signingCertTrustCondition = new SigningCertTrustCondition();
                            this.signingCertTrustCondition.parse(object);
                            break;
                        case timeStampTrustCondition:
                            this.timeStampTrustCondition = new TimestampTrustCondition();
                            this.timeStampTrustCondition.parse(object);
                            break;
                        case attributeTrustCondition:
                            this.attributeTrustCondition = new AttributeTrustCondition();
                            this.attributeTrustCondition.parse(object);
                            break;
                        case algorithmConstraintSet:
                            this.algorithmConstraintSet = new AlgorithmConstraintSet();
                            this.algorithmConstraintSet.parse(object);
                            break;
                        case signPolExtensions:
                            this.signPolExtensions = new SignPolExtensions();
                            this.signPolExtensions.parse(object);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

    enum TAG {

        signerAndVeriferRules(0),
        signingCertTrustCondition(1),
        timeStampTrustCondition(2),
        attributeTrustCondition(3),
        algorithmConstraintSet(4),
        signPolExtensions(5);

        private final int value;

        private TAG(int value) {
            this.value = value;
        }

        public static TAG getTag(int value) {
            for (TAG tag : TAG.values()) {
                if (tag.value == value) {
                    return tag;
                }
            }
            return null;
        }
    }
}
