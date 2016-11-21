package org.demoiselle.signer.signature.policy.engine.asn1.etsi;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.demoiselle.signer.signature.policy.engine.asn1.ASN1Object;

public class SignaturePolicy {

    private AlgorithmIdentifier signPolicyHashAlg;
    private SignPolicyInfo signPolicyInfo;
    private SignPolicyHash signPolicyHash;

    public AlgorithmIdentifier getSignPolicyHashAlg() {
        return signPolicyHashAlg;
    }

    public void setSignPolicyHashAlg(AlgorithmIdentifier signPolicyHashAlg) {
        this.signPolicyHashAlg = signPolicyHashAlg;
    }

    public SignPolicyInfo getSignPolicyInfo() {
        return signPolicyInfo;
    }

    public void setSignPolicyInfo(SignPolicyInfo signPolicyInfo) {
        this.signPolicyInfo = signPolicyInfo;
    }

    public SignPolicyHash getSignPolicyHash() {
        return signPolicyHash;
    }

    public void setSignPolicyHash(SignPolicyHash signPolicyHash) {
        this.signPolicyHash = signPolicyHash;
    }

    public void parse(ASN1Primitive derObject) {
        ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
        this.signPolicyHashAlg = new AlgorithmIdentifier();
        this.signPolicyHashAlg.parse(derSequence.getObjectAt(0).toASN1Primitive());
        this.signPolicyInfo = new SignPolicyInfo();
        this.signPolicyInfo.parse(derSequence.getObjectAt(1).toASN1Primitive());
        if (derSequence.size() == 3) {
            this.signPolicyHash = new SignPolicyHash();
            this.signPolicyHash.parse(derSequence.getObjectAt(2).toASN1Primitive());
        }
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("Algoritmo Hash da Política.......: ").append(this.getSignPolicyHashAlg().getAlgorithm().getValue()).append("\n");
        builder.append("Hash da Política.................: ").append(this.getSignPolicyHash().getValue()).append("\n");
        builder.append("OID da Política..................: ").append(this.getSignPolicyInfo().getSignPolicyIdentifier().getValue()).append("\n");
        builder.append("Data Lancamento da Política......: ").append(this.getSignPolicyInfo().getDateOfIssue().getDate()).append("\n");
        builder.append("Emissor da Política..............: ").append(this.getSignPolicyInfo().getPolicyIssuerName()).append("\n");
        builder.append("Campo de aplicação da Política...: ").append(this.getSignPolicyInfo().getFieldOfApplication().getValue()).append("\n");
        builder.append("Politica válida entre............: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()).append("\n");
        builder.append("External Signed Data.............: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getExternalSignedData()).append("\n");
        builder.append("MandatedCertificateRef...........: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateRef()).append("\n");
        builder.append("MandatedCertificateInfo..........: ").append(this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedCertificateInfo()).append("\n");

        for (AlgAndLength oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getAlgorithmConstraintSet().getSignerAlgorithmConstraints().getAlgAndLengths()) {
            builder.append("Algoritmo de assinatura..........: ").append(oi.getAlgID()).append("\n");
            builder.append("Tamanho mínimo da chave..........: ").append(oi.getMinKeyLength()).append("\n");
        }

        builder.append("==============================================================").append("\n");
        for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedSignedAttr().getObjectIdentifiers()) {
            builder.append("OID de atributos assinados.......: ").append(oi.getValue()).append("\n");
        }

        builder.append("==============================================================").append("\n");

        if (this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
            for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
                builder.append("OID de atributos nao assinados...: ").append(oi.getValue()).append("\n");
            }
        }

        if (this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
            builder.append("==============================================================").append("\n");
            for (ObjectIdentifier oi : this.getSignPolicyInfo().getSignatureValidationPolicy().getCommonRules().getSignerAndVeriferRules().getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
                builder.append("OID de atributos nao assinados...: ").append(oi.getValue()).append("\n");
            }
        }

        return builder.toString();
    }

}
