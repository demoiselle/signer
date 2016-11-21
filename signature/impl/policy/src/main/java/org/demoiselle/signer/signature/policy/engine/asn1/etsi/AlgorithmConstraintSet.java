package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

/**
 * The algorithmConstrains fields, if present, identifies the signing algorithms
 * (hash, public key cryptography, combined hash and public key cryptography)
 * that may be used for specific purposes and any minimum length. If this field
 * is not present then the policy applies no constraints.
 *
 */
public class AlgorithmConstraintSet extends ASN1Object {

    public enum TAG {

        signerAlgorithmConstraints(0), eeCertAlgorithmConstraints(1),
        caCertAlgorithmConstraints(2), aaCertAlgorithmConstraints(3),
        tsaCertAlgorithmConstraints(4);
        int value;

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

    private AlgorithmConstraints signerAlgorithmConstraints;
    private AlgorithmConstraints eeCertAlgorithmConstraints;
    private AlgorithmConstraints caCertAlgorithmConstraints;
    private AlgorithmConstraints aaCertAlgorithmConstraints;
    private AlgorithmConstraints tsaCertAlgorithmConstraints;

    public AlgorithmConstraints getSignerAlgorithmConstraints() {
        return signerAlgorithmConstraints;
    }

    public void setSignerAlgorithmConstraints(
            AlgorithmConstraints signerAlgorithmConstraints) {
        this.signerAlgorithmConstraints = signerAlgorithmConstraints;
    }

    public AlgorithmConstraints getEeCertAlgorithmConstraints() {
        return eeCertAlgorithmConstraints;
    }

    public void setEeCertAlgorithmConstraints(
            AlgorithmConstraints eeCertAlgorithmConstraints) {
        this.eeCertAlgorithmConstraints = eeCertAlgorithmConstraints;
    }

    public AlgorithmConstraints getCaCertAlgorithmConstraints() {
        return caCertAlgorithmConstraints;
    }

    public void setCaCertAlgorithmConstraints(
            AlgorithmConstraints caCertAlgorithmConstraints) {
        this.caCertAlgorithmConstraints = caCertAlgorithmConstraints;
    }

    public AlgorithmConstraints getAaCertAlgorithmConstraints() {
        return aaCertAlgorithmConstraints;
    }

    public void setAaCertAlgorithmConstraints(
            AlgorithmConstraints aaCertAlgorithmConstraints) {
        this.aaCertAlgorithmConstraints = aaCertAlgorithmConstraints;
    }

    public AlgorithmConstraints getTsaCertAlgorithmConstraints() {
        return tsaCertAlgorithmConstraints;
    }

    public void setTsaCertAlgorithmConstraints(
            AlgorithmConstraints tsaCertAlgorithmConstraints) {
        this.tsaCertAlgorithmConstraints = tsaCertAlgorithmConstraints;
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
                        case signerAlgorithmConstraints:
                            this.signerAlgorithmConstraints = new AlgorithmConstraints();
                            this.signerAlgorithmConstraints.parse(object);
                            break;
                        case eeCertAlgorithmConstraints:
                            this.eeCertAlgorithmConstraints = new AlgorithmConstraints();
                            this.eeCertAlgorithmConstraints.parse(object);
                            break;
                        case caCertAlgorithmConstraints:
                            this.caCertAlgorithmConstraints = new AlgorithmConstraints();
                            this.caCertAlgorithmConstraints.parse(object);
                            break;
                        case aaCertAlgorithmConstraints:
                            this.aaCertAlgorithmConstraints = new AlgorithmConstraints();
                            this.aaCertAlgorithmConstraints.parse(object);
                            break;
                        case tsaCertAlgorithmConstraints:
                            this.tsaCertAlgorithmConstraints = new AlgorithmConstraints();
                            this.tsaCertAlgorithmConstraints.parse(object);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

}
