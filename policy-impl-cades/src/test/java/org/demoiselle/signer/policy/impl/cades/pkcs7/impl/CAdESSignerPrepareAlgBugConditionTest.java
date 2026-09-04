package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgAndLength;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgorithmConstraintSet;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgorithmConstraints;
import org.demoiselle.signer.policy.engine.asn1.etsi.AlgorithmIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.CommonRules;
import org.demoiselle.signer.policy.engine.asn1.etsi.ObjectIdentifier;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignPolicyInfo;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignatureValidationPolicy;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Teste de exploração da condição de bug: signPolicyHashAlg é sobrescrito
 * após chamada a prepareAlgAndLength().
 *
 * <p>Este teste DEVE FALHAR no código não-corrigido, confirmando a existência do bug.
 * A falha demonstra que o OID do hash da política (SHA-256: 2.16.840.1.101.3.4.2.1)
 * é indevidamente sobrescrito pelo OID do hash do algoritmo de assinatura
 * (SHA-512: 2.16.840.1.101.3.4.2.3).
 *
 * <p><b>Validates: Requirements 1.1, 1.2, 1.3</b>
 */
public class CAdESSignerPrepareAlgBugConditionTest {

    // OID SHA-256 (hash da política original)
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
    // OID SHA-512 (hash do algoritmo SHA512withRSA/SHA512withECDSA)
    private static final String SHA512_OID = "2.16.840.1.101.3.4.2.3";

    // OID do algoritmo de cifra SHA512withRSA (usado na lista AlgAndLength)
    private static final String SHA512_WITH_RSA_CIPHER_OID = "1.2.840.113549.1.1.13";
    // OID do algoritmo de cifra SHA256withRSA
    private static final String SHA256_WITH_RSA_CIPHER_OID = "1.2.840.113549.1.1.11";

    private static X509Certificate testCertificate;

    @BeforeClass
    public static void gerarCertificadoTeste() throws Exception {
        java.security.Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name issuer = new X500Name("CN=Teste Bug Condition");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
        Date notAfter = new Date(System.currentTimeMillis() + 86400000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(keyPair.getPrivate());

        testCertificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));
    }

    /**
     * Cria um CAdESSigner com uma SignaturePolicy customizada para teste.
     * A política é configurada com signPolicyHashAlg = SHA-256 e uma lista
     * de algoritmos contendo SHA512withRSA e SHA256withRSA.
     */
    private CAdESSigner criarSignerComPoliticaCustomizada() throws Exception {
        CAdESSigner signer = new CAdESSigner();

        // Injetar certificado de teste para evitar NPE na validação de tamanho de chave
        Field certField = CAdESSigner.class.getDeclaredField("certificate");
        certField.setAccessible(true);
        certField.set(signer, testCertificate);

        // Construir a SignaturePolicy com signPolicyHashAlg = SHA-256
        SignaturePolicy signaturePolicy = new SignaturePolicy();

        // signPolicyHashAlg = SHA-256
        AlgorithmIdentifier hashAlg = new AlgorithmIdentifier();
        ObjectIdentifier hashOid = new ObjectIdentifier();
        hashOid.setValue(SHA256_OID);
        hashAlg.setAlgorithm(hashOid);
        signaturePolicy.setSignPolicyHashAlg(hashAlg);

        // Construir a cadeia: SignPolicyInfo -> SignatureValidationPolicy -> CommonRules -> AlgorithmConstraintSet
        SignPolicyInfo signPolicyInfo = new SignPolicyInfo();
        SignatureValidationPolicy svp = new SignatureValidationPolicy();
        CommonRules commonRules = new CommonRules();

        // AlgorithmConstraintSet com signerAlgorithmConstraints
        AlgorithmConstraintSet algorithmConstraintSet = new AlgorithmConstraintSet();
        AlgorithmConstraints signerConstraints = new AlgorithmConstraints();

        // Lista de AlgAndLength: SHA256withRSA (index 0) e SHA512withRSA (index 1)
        // Nota: branch else usa listOfAlgAndLength.get(1), que será SHA512withRSA
        Collection<AlgAndLength> algAndLengths = new ArrayList<AlgAndLength>();

        // Primeiro item: SHA256withRSA (OID do cipher: 1.2.840.113549.1.1.11)
        AlgAndLength alg1 = new AlgAndLength();
        ObjectIdentifier oid1 = new ObjectIdentifier();
        oid1.setValue(SHA256_WITH_RSA_CIPHER_OID);
        alg1.setAlgID(oid1);
        alg1.setMinKeyLength(2048);
        algAndLengths.add(alg1);

        // Segundo item: SHA512withRSA (OID do cipher: 1.2.840.113549.1.1.13)
        AlgAndLength alg2 = new AlgAndLength();
        ObjectIdentifier oid2 = new ObjectIdentifier();
        oid2.setValue(SHA512_WITH_RSA_CIPHER_OID);
        alg2.setAlgID(oid2);
        alg2.setMinKeyLength(2048);
        algAndLengths.add(alg2);

        signerConstraints.setAlgAndLengths(algAndLengths);
        algorithmConstraintSet.setSignerAlgorithmConstraints(signerConstraints);
        commonRules.setAlgorithmConstraintSet(algorithmConstraintSet);
        svp.setCommonRules(commonRules);
        signPolicyInfo.setSignatureValidationPolicy(svp);
        signaturePolicy.setSignPolicyInfo(signPolicyInfo);

        // Usar reflection para substituir o campo signaturePolicy no CAdESSigner
        Field signaturePolicyField = CAdESSigner.class.getDeclaredField("signaturePolicy");
        signaturePolicyField.setAccessible(true);
        signaturePolicyField.set(signer, signaturePolicy);

        return signer;
    }

    /**
     * Caso 1 (branch if): Algoritmo "SHA512withRSA" informado como parâmetro.
     *
     * <p>O signPolicyHashAlg da política é SHA-256 (OID: 2.16.840.1.101.3.4.2.1).
     * Após prepareAlgAndLength(), o valor DEVE permanecer SHA-256.
     *
     * <p>No código com bug, o valor é sobrescrito para SHA-512 (OID: 2.16.840.1.101.3.4.2.3),
     * causando a falha deste teste — o que confirma a existência do bug.
     */
    @Test
    public void testBranchIf_SHA512withRSA_devPreservarSignPolicyHashAlg() throws Exception {
        CAdESSigner signer = criarSignerComPoliticaCustomizada();

        // Configurar algoritmo = SHA512withRSA (branch if)
        signer.setAlgorithm("SHA512withRSA");

        // Capturar o valor original do signPolicyHashAlg
        Field signaturePolicyField = CAdESSigner.class.getDeclaredField("signaturePolicy");
        signaturePolicyField.setAccessible(true);
        SignaturePolicy policy = (SignaturePolicy) signaturePolicyField.get(signer);
        String originalHashAlgOID = policy.getSignPolicyHashAlg().getAlgorithm().getValue();
        assertEquals("Pré-condição: signPolicyHashAlg deve ser SHA-256",
                SHA256_OID, originalHashAlgOID);

        // Executar o método sob teste
        signer.prepareAlgAndLength();

        // Verificar que signPolicyHashAlg NÃO foi modificado
        String hashAlgAposChamada = policy.getSignPolicyHashAlg().getAlgorithm().getValue();
        assertEquals(
                "signPolicyHashAlg deve permanecer SHA-256 (2.16.840.1.101.3.4.2.1) após prepareAlgAndLength(). "
                        + "Se mudou para SHA-512 (2.16.840.1.101.3.4.2.3), o bug está presente.",
                SHA256_OID, hashAlgAposChamada);
    }

    /**
     * Caso 2 (branch else): Nenhum algoritmo informado — seleção automática da lista.
     *
     * <p>Quando nenhum algoritmo é informado, prepareAlgAndLength() seleciona
     * listOfAlgAndLength.get(1) (SHA256withRSA). O signPolicyHashAlg deve permanecer SHA-256.
     *
     * <p>No código com bug, o valor é sobrescrito com o hash do algoritmo selecionado,
     * causando a falha deste teste.
     */
    @Test
    public void testBranchElse_semAlgoritmo_devPreservarSignPolicyHashAlg() throws Exception {
        CAdESSigner signer = criarSignerComPoliticaCustomizada();

        // Não configurar algoritmo (branch else) - usar reflection para garantir null
        signer.setAlgorithm((String) null);

        // Capturar o valor original do signPolicyHashAlg
        Field signaturePolicyField = CAdESSigner.class.getDeclaredField("signaturePolicy");
        signaturePolicyField.setAccessible(true);
        SignaturePolicy policy = (SignaturePolicy) signaturePolicyField.get(signer);
        String originalHashAlgOID = policy.getSignPolicyHashAlg().getAlgorithm().getValue();
        assertEquals("Pré-condição: signPolicyHashAlg deve ser SHA-256",
                SHA256_OID, originalHashAlgOID);

        // Executar o método sob teste
        signer.prepareAlgAndLength();

        // Verificar que signPolicyHashAlg NÃO foi modificado
        String hashAlgAposChamada = policy.getSignPolicyHashAlg().getAlgorithm().getValue();
        assertEquals(
                "signPolicyHashAlg deve permanecer SHA-256 (2.16.840.1.101.3.4.2.1) após prepareAlgAndLength(). "
                        + "Se mudou para SHA-512 (2.16.840.1.101.3.4.2.3), o bug está presente no branch else.",
                SHA256_OID, hashAlgAposChamada);
    }

    /**
     * Caso 3 (branch if, ECDSA): Algoritmo "SHA512withECDSA" informado.
     *
     * <p>Verifica que o bug também se manifesta com ECDSA.
     * O signPolicyHashAlg (SHA-256) deve permanecer inalterado.
     *
     * <p>No código com bug, o valor é sobrescrito para SHA-512 (hash do SHA512withECDSA).
     *
     * <p>Nota: SHA512withECDSA não está na lista de AlgAndLength configurada (que usa
     * OIDs de cipher RSA), então este teste precisa de uma lista que inclua o OID ECDSA.
     */
    @Test
    public void testBranchIf_SHA512withECDSA_devPreservarSignPolicyHashAlg() throws Exception {
        CAdESSigner signer = new CAdESSigner();

        // Injetar certificado de teste
        Field certField = CAdESSigner.class.getDeclaredField("certificate");
        certField.setAccessible(true);
        certField.set(signer, testCertificate);

        // Construir a SignaturePolicy com signPolicyHashAlg = SHA-256
        SignaturePolicy signaturePolicy = new SignaturePolicy();
        AlgorithmIdentifier hashAlg = new AlgorithmIdentifier();
        ObjectIdentifier hashOid = new ObjectIdentifier();
        hashOid.setValue(SHA256_OID);
        hashAlg.setAlgorithm(hashOid);
        signaturePolicy.setSignPolicyHashAlg(hashAlg);

        // Cadeia com lista contendo SHA512withECDSA (OID cipher ECDSA: 1.0.14888.3.0.4)
        SignPolicyInfo signPolicyInfo = new SignPolicyInfo();
        SignatureValidationPolicy svp = new SignatureValidationPolicy();
        CommonRules commonRules = new CommonRules();
        AlgorithmConstraintSet algorithmConstraintSet = new AlgorithmConstraintSet();
        AlgorithmConstraints signerConstraints = new AlgorithmConstraints();

        Collection<AlgAndLength> algAndLengths = new ArrayList<AlgAndLength>();

        // Item com OID de cipher ECDSA (1.0.14888.3.0.4) — usado por SHA512withECDSA e SHA256withECDSA
        AlgAndLength algEcdsa = new AlgAndLength();
        ObjectIdentifier oidEcdsa = new ObjectIdentifier();
        oidEcdsa.setValue("1.0.14888.3.0.4"); // OID cipher ECDSA
        algEcdsa.setAlgID(oidEcdsa);
        algEcdsa.setMinKeyLength(256);
        algAndLengths.add(algEcdsa);

        // Segundo item (necessário para branch else não dar IndexOutOfBounds)
        AlgAndLength alg2 = new AlgAndLength();
        ObjectIdentifier oid2 = new ObjectIdentifier();
        oid2.setValue(SHA256_WITH_RSA_CIPHER_OID);
        alg2.setAlgID(oid2);
        alg2.setMinKeyLength(2048);
        algAndLengths.add(alg2);

        signerConstraints.setAlgAndLengths(algAndLengths);
        algorithmConstraintSet.setSignerAlgorithmConstraints(signerConstraints);
        commonRules.setAlgorithmConstraintSet(algorithmConstraintSet);
        svp.setCommonRules(commonRules);
        signPolicyInfo.setSignatureValidationPolicy(svp);
        signaturePolicy.setSignPolicyInfo(signPolicyInfo);

        // Usar reflection para injetar a política customizada
        Field signaturePolicyField = CAdESSigner.class.getDeclaredField("signaturePolicy");
        signaturePolicyField.setAccessible(true);
        signaturePolicyField.set(signer, signaturePolicy);

        // Configurar algoritmo = SHA512withECDSA (branch if)
        signer.setAlgorithm("SHA512withECDSA");

        // Verificar pré-condição
        SignaturePolicy policy = (SignaturePolicy) signaturePolicyField.get(signer);
        assertEquals("Pré-condição: signPolicyHashAlg deve ser SHA-256",
                SHA256_OID, policy.getSignPolicyHashAlg().getAlgorithm().getValue());

        // Executar o método sob teste
        signer.prepareAlgAndLength();

        // Verificar que signPolicyHashAlg NÃO foi modificado
        String hashAlgAposChamada = policy.getSignPolicyHashAlg().getAlgorithm().getValue();
        assertEquals(
                "signPolicyHashAlg deve permanecer SHA-256 (2.16.840.1.101.3.4.2.1) após prepareAlgAndLength(). "
                        + "Se mudou para SHA-512 (2.16.840.1.101.3.4.2.3), o bug está presente.",
                SHA256_OID, hashAlgAposChamada);
    }
}
