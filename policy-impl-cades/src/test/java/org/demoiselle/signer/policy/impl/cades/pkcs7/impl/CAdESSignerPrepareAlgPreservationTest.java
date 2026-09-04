package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

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
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignerException;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Testes de preservação do comportamento de seleção de algoritmo e configuração
 * do pkcs1 em prepareAlgAndLength(). Estes testes verificam comportamentos que
 * NÃO são afetados pelo bug da sobrescrita de signPolicyHashAlg e devem
 * passar tanto no código não-corrigido quanto no código corrigido.
 *
 * <p><b>Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5</b>
 */
public class CAdESSignerPrepareAlgPreservationTest {

    // OID SHA-256 (hash da política)
    private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";

    // OIDs de cipher para a lista AlgAndLength
    private static final String SHA512_WITH_RSA_CIPHER_OID = "1.2.840.113549.1.1.13";
    private static final String SHA256_WITH_RSA_CIPHER_OID = "1.2.840.113549.1.1.11";

    private static X509Certificate testCertificate;

    @BeforeClass
    public static void gerarCertificadoTeste() throws Exception {
        java.security.Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name issuer = new X500Name("CN=Teste Preservation");
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
     * A política é configurada com signPolicyHashAlg = SHA-256 e a lista de
     * algoritmos fornecida.
     */
    private CAdESSigner criarSignerComListaDeAlgoritmos(Collection<AlgAndLength> algAndLengths) throws Exception {
        CAdESSigner signer = new CAdESSigner();

        // Injetar certificado de teste para evitar NPE na validação de tamanho de chave
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

        // Cadeia: SignPolicyInfo -> SignatureValidationPolicy -> CommonRules -> AlgorithmConstraintSet
        SignPolicyInfo signPolicyInfo = new SignPolicyInfo();
        SignatureValidationPolicy svp = new SignatureValidationPolicy();
        CommonRules commonRules = new CommonRules();

        AlgorithmConstraintSet algorithmConstraintSet = new AlgorithmConstraintSet();
        AlgorithmConstraints signerConstraints = new AlgorithmConstraints();

        signerConstraints.setAlgAndLengths(algAndLengths);
        algorithmConstraintSet.setSignerAlgorithmConstraints(signerConstraints);
        commonRules.setAlgorithmConstraintSet(algorithmConstraintSet);
        svp.setCommonRules(commonRules);
        signPolicyInfo.setSignatureValidationPolicy(svp);
        signaturePolicy.setSignPolicyInfo(signPolicyInfo);

        // Injetar a política customizada via reflection
        Field signaturePolicyField = CAdESSigner.class.getDeclaredField("signaturePolicy");
        signaturePolicyField.setAccessible(true);
        signaturePolicyField.set(signer, signaturePolicy);

        return signer;
    }

    /**
     * Cria um CAdESSigner com algorithmConstraintSet = null (cenário de fallback).
     */
    private CAdESSigner criarSignerSemAlgorithmConstraintSet() throws Exception {
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

        // Cadeia com algorithmConstraintSet = null
        SignPolicyInfo signPolicyInfo = new SignPolicyInfo();
        SignatureValidationPolicy svp = new SignatureValidationPolicy();
        CommonRules commonRules = new CommonRules();
        // Não configurar algorithmConstraintSet — fica null
        svp.setCommonRules(commonRules);
        signPolicyInfo.setSignatureValidationPolicy(svp);
        signaturePolicy.setSignPolicyInfo(signPolicyInfo);

        Field signaturePolicyField = CAdESSigner.class.getDeclaredField("signaturePolicy");
        signaturePolicyField.setAccessible(true);
        signaturePolicyField.set(signer, signaturePolicy);

        return signer;
    }

    /**
     * Cria a lista padrão de algoritmos: SHA256withRSA (index 0) e SHA512withRSA (index 1).
     */
    private Collection<AlgAndLength> criarListaPadrao() {
        Collection<AlgAndLength> algAndLengths = new ArrayList<AlgAndLength>();

        // Index 0: SHA256withRSA (OID cipher: 1.2.840.113549.1.1.11)
        AlgAndLength alg1 = new AlgAndLength();
        ObjectIdentifier oid1 = new ObjectIdentifier();
        oid1.setValue(SHA256_WITH_RSA_CIPHER_OID);
        alg1.setAlgID(oid1);
        alg1.setMinKeyLength(2048);
        algAndLengths.add(alg1);

        // Index 1: SHA512withRSA (OID cipher: 1.2.840.113549.1.1.13)
        AlgAndLength alg2 = new AlgAndLength();
        ObjectIdentifier oid2 = new ObjectIdentifier();
        oid2.setValue(SHA512_WITH_RSA_CIPHER_OID);
        alg2.setAlgID(oid2);
        alg2.setMinKeyLength(2048);
        algAndLengths.add(alg2);

        return algAndLengths;
    }

    // ===========================================================================================
    // Test 1: Seleção de AlgAndLength preservada (branch if)
    // Para qualquer algoritmo informado que esteja na lista da política,
    // o AlgAndLength retornado deve ter o mesmo algID e minKeyLength.
    // ===========================================================================================

    /**
     * Quando pkcs1.algorithm = "SHA512withRSA" e este algoritmo está na lista da política,
     * prepareAlgAndLength() deve retornar AlgAndLength com algID = OID do SHA512withRSA
     * (1.2.840.113549.1.1.13) e minKeyLength = 2048.
     *
     * <p>Este comportamento é preservado porque se refere ao RETORNO do método,
     * não à sobrescrita de signPolicyHashAlg.
     */
    @Test
    public void testBranchIf_selecaoAlgAndLength_SHA512withRSA() throws Exception {
        CAdESSigner signer = criarSignerComListaDeAlgoritmos(criarListaPadrao());
        signer.setAlgorithm("SHA512withRSA");

        AlgAndLength resultado = signer.prepareAlgAndLength();

        assertNotNull("AlgAndLength retornado não deve ser null", resultado);
        assertEquals("AlgID deve ser o OID do SHA512withRSA",
                SHA512_WITH_RSA_CIPHER_OID, resultado.getAlgID().getValue());
        assertEquals("MinKeyLength deve ser 2048",
                Integer.valueOf(2048), resultado.getMinKeyLength());
    }

    /**
     * Quando pkcs1.algorithm = "SHA256withRSA" e este algoritmo está na lista da política,
     * prepareAlgAndLength() deve retornar AlgAndLength com algID = OID do SHA256withRSA
     * (1.2.840.113549.1.1.11) e minKeyLength = 2048.
     */
    @Test
    public void testBranchIf_selecaoAlgAndLength_SHA256withRSA() throws Exception {
        CAdESSigner signer = criarSignerComListaDeAlgoritmos(criarListaPadrao());
        signer.setAlgorithm("SHA256withRSA");

        AlgAndLength resultado = signer.prepareAlgAndLength();

        assertNotNull("AlgAndLength retornado não deve ser null", resultado);
        assertEquals("AlgID deve ser o OID do SHA256withRSA",
                SHA256_WITH_RSA_CIPHER_OID, resultado.getAlgID().getValue());
        assertEquals("MinKeyLength deve ser 2048",
                Integer.valueOf(2048), resultado.getMinKeyLength());
    }

    // ===========================================================================================
    // Test 2: Configuração do pkcs1 no branch else
    // No branch else, pkcs1.algorithm deve ser configurado com o nome do algoritmo
    // correspondente ao segundo item da lista (index 1).
    // ===========================================================================================

    /**
     * Quando nenhum algoritmo é informado (branch else), prepareAlgAndLength()
     * seleciona listOfAlgAndLength.get(1) (SHA512withRSA) e configura
     * pkcs1.algorithm com "SHA512withRSA".
     *
     * <p>O retorno deve ser o AlgAndLength do segundo item da lista.
     */
    @Test
    public void testBranchElse_configuraPkcs1ComSegundoItemDaLista() throws Exception {
        CAdESSigner signer = criarSignerComListaDeAlgoritmos(criarListaPadrao());
        signer.setAlgorithm((String) null);

        AlgAndLength resultado = signer.prepareAlgAndLength();

        // Verifica o retorno: deve ser o segundo item (SHA512withRSA)
        assertNotNull("AlgAndLength retornado não deve ser null", resultado);
        assertEquals("AlgID deve ser o OID do SHA512withRSA (segundo item da lista)",
                SHA512_WITH_RSA_CIPHER_OID, resultado.getAlgID().getValue());
        assertEquals("MinKeyLength deve ser 2048",
                Integer.valueOf(2048), resultado.getMinKeyLength());

        // Verifica que pkcs1.algorithm foi configurado com o nome correspondente
        // AlgorithmNames.getAlgorithmNameByOID("1.2.840.113549.1.1.13") = "SHA512withRSA"
        assertEquals("pkcs1.algorithm deve ser configurado com SHA512withRSA",
                "SHA512withRSA", signer.getAlgorithm());
    }

    // ===========================================================================================
    // Test 3: Exceção para algoritmo não permitido pela política
    // Quando o algoritmo informado não está na lista da política,
    // prepareAlgAndLength() lança SignerException.
    // ===========================================================================================

    /**
     * Quando pkcs1.algorithm = "SHA1withRSA" e este algoritmo NÃO está na lista
     * da política (que só contém SHA256withRSA e SHA512withRSA),
     * prepareAlgAndLength() deve lançar SignerException com a mensagem
     * "error.no.algorithm.policy".
     *
     * <p>Na verdade, o código itera a lista sem encontrar match, então algAndLength
     * permanece null, e o throw final é executado.
     */
    @Test(expected = SignerException.class)
    public void testBranchIf_algoritmoNaoPermitido_lancaSignerException() throws Exception {
        CAdESSigner signer = criarSignerComListaDeAlgoritmos(criarListaPadrao());
        // SHA1withRSA -> OID cipher = 1.2.840.113549.1.1.5 (não está na lista)
        signer.setAlgorithm("SHA1withRSA");

        signer.prepareAlgAndLength();
        // Deve lançar SignerException
    }

    // ===========================================================================================
    // Test 4: Fallback quando algorithmConstraintSet é null
    // Retorna AlgAndLength com algoritmo configurado ou DEFAULT e minKeyLength = 0.
    // ===========================================================================================

    /**
     * Quando algorithmConstraintSet é null e pkcs1.algorithm está configurado
     * ("SHA512withRSA"), prepareAlgAndLength() deve retornar um AlgAndLength
     * com algID = OID do algoritmo configurado e minKeyLength = 0.
     */
    @Test
    public void testFallback_algorithmConstraintSetNull_comAlgoritmoConfigurado() throws Exception {
        CAdESSigner signer = criarSignerSemAlgorithmConstraintSet();
        signer.setAlgorithm("SHA512withRSA");

        AlgAndLength resultado = signer.prepareAlgAndLength();

        assertNotNull("AlgAndLength retornado não deve ser null", resultado);
        // AlgorithmNames.getOIDByAlgorithmName("SHA512withRSA") = "1.2.840.113549.1.1.13"
        assertEquals("AlgID deve ser o OID do SHA512withRSA",
                SHA512_WITH_RSA_CIPHER_OID, resultado.getAlgID().getValue());
        assertEquals("MinKeyLength deve ser 0 (fallback sem restrição)",
                Integer.valueOf(0), resultado.getMinKeyLength());
    }

    /**
     * Quando algorithmConstraintSet é null e nenhum algoritmo está configurado,
     * prepareAlgAndLength() deve usar o DEFAULT (SHA512withRSA) e retornar
     * AlgAndLength com algID = OID do DEFAULT e minKeyLength = 0.
     */
    @Test
    public void testFallback_algorithmConstraintSetNull_semAlgoritmoConfigurado() throws Exception {
        CAdESSigner signer = criarSignerSemAlgorithmConstraintSet();
        signer.setAlgorithm((String) null);

        AlgAndLength resultado = signer.prepareAlgAndLength();

        assertNotNull("AlgAndLength retornado não deve ser null", resultado);
        // SignerAlgorithmEnum.DEFAULT = SHA512withRSA
        // AlgorithmNames.getOIDByAlgorithmName("SHA512withRSA") = "1.2.840.113549.1.1.13"
        String expectedOID = "1.2.840.113549.1.1.13"; // OID do DEFAULT (SHA512withRSA)
        assertEquals("AlgID deve ser o OID do algoritmo DEFAULT (SHA512withRSA)",
                expectedOID, resultado.getAlgID().getValue());
        assertEquals("MinKeyLength deve ser 0 (fallback sem restrição)",
                Integer.valueOf(0), resultado.getMinKeyLength());
    }
}
