package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class CertificateTrustPoint extends ASN1Object {

    enum TAG {

        pathLenConstraint(0), acceptablePolicySet(1), nameConstraints(2), policyConstraints(3);
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

    private X509Certificate trustpoint;
    private PathLenConstraint pathLenConstraint;
    private AcceptablePolicySet acceptablePolicySet;
    private NameConstraints nameConstraints;
    private PolicyConstraints policyConstraints;

    public X509Certificate getTrustpoint() {
        return trustpoint;
    }

    public void setTrustpoint(X509Certificate trustpoint) {
        this.trustpoint = trustpoint;
    }

    public PathLenConstraint getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(PathLenConstraint pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    public AcceptablePolicySet getAcceptablePolicySet() {
        return acceptablePolicySet;
    }

    public void setAcceptablePolicySet(AcceptablePolicySet acceptablePolicySet) {
        this.acceptablePolicySet = acceptablePolicySet;
    }

    public NameConstraints getNameConstraints() {
        return nameConstraints;
    }

    public void setNameConstraints(NameConstraints nameConstraints) {
        this.nameConstraints = nameConstraints;
    }

    public PolicyConstraints getPolicyConstraints() {
        return policyConstraints;
    }

    public void setPolicyConstraints(PolicyConstraints policyConstraints) {
        this.policyConstraints = policyConstraints;
    }

    @Override
    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        DERSequence x509Sequence = (DERSequence) derSequence.getObjectAt(0).toASN1Primitive();
        try {
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(x509Sequence.getEncoded());
            this.trustpoint = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(byteArrayInputStream);
        } catch (Throwable error) {
            error.printStackTrace();
        }

        int total = derSequence.size();

        if (total > 0) {
            for (int i = 0; i < total; i++) {
                ASN1Primitive object = derSequence.getObjectAt(i).toASN1Primitive();
                if (object instanceof DERTaggedObject) {
                    DERTaggedObject derTaggedObject = (DERTaggedObject) object;
                    TAG tag = TAG.getTag(derTaggedObject.getTagNo());
                    switch (tag) {
                        case pathLenConstraint:
                            this.pathLenConstraint = new PathLenConstraint();
                            this.pathLenConstraint.parse(object);
                            break;
                        case acceptablePolicySet:
                            this.acceptablePolicySet = new AcceptablePolicySet();
                            this.acceptablePolicySet.parse(object);
                            break;
                        case nameConstraints:
                            this.nameConstraints = new NameConstraints();
                            this.nameConstraints.parse(object);

                            break;
                        case policyConstraints:
                            this.policyConstraints = new PolicyConstraints();
                            this.policyConstraints.parse(object);
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }

}
