/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.demoiselle.signer.policy.impl.cades.pkcs7.attribute.impl.IdSigningPolicy;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Teste de integracao fim-a-fim do fluxo de montagem do atributo
 * {@code SignaturePolicyIdentifier} (id-aa-ets-sigPolicyId,
 * {@link PKCSObjectIdentifiers#id_aa_ets_sigPolicyId}) na assinatura CAdES,
 * validando a extensao de recalculo/verificacao do hash da politica
 * (spec {@code hash-algoritmo-politica-fix}).
 *
 * <p><b>Caminho de integracao utilizado</b>: como {@code doAttachedSign}/
 * {@code prepareSignedAttributes} disparam {@code checkCertificateChain()}
 * (validacao ICP-Brasil), que falha com certificado self-signed, o teste
 * exercita o nivel imediatamente abaixo, que e exatamente o caminho de montagem
 * do atributo com recalculo:
 * <ol>
 *   <li>Constroi um {@link CAdESSigner} com algoritmo de assinatura
 *       {@code SHA512withRSA} e a politica real {@code AD_RB_CADES_2_3}
 *       (carregada via {@link PolicyFactory#loadPolicy(Policies)} pelo
 *       construtor), exatamente o cenario do bug.</li>
 *   <li>Injeta uma chave privada/certificado RSA 2048 self-signed (mesmo padrao
 *       BouncyCastle dos testes existentes) e executa
 *       {@link CAdESSigner#prepareAlgAndLength()} para reproduzir o cenario onde
 *       o bug original poderia sobrescrever {@code signPolicyHashAlg}.</li>
 *   <li>Monta o atributo {@code SignaturePolicyIdentifier} via
 *       {@link IdSigningPolicy#initialize} + {@link IdSigningPolicy#getValue()},
 *       consumindo a mesma {@link SignaturePolicy} real usada pelo signer.</li>
 *   <li>Parseia o {@link SignaturePolicyId} e assere sobre
 *       {@code sigPolicyHash.hashAlgorithm} e {@code sigPolicyHash.hashValue}.</li>
 * </ol>
 *
 * <p>Isto e um teste de integracao real do caminho de montagem do atributo com
 * recalculo, sem depender da infraestrutura de validacao de cadeia ICP.
 *
 * <p><b>Validates: Requirements 2.2, 2.4, 5.1, 5.2, 6.4</b>
 */
public class CAdESPolicyHashIntegrationTest {

	private static final Logger logger = LoggerFactory.getLogger(CAdESPolicyHashIntegrationTest.class);

	/** OID SHA-256 (hash da politica AD-RB CAdES 2.3). */
	private static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
	/** OID SHA-512 (hash derivado de SHA512withRSA) - NAO deve aparecer no atributo. */
	private static final String SHA512_OID = "2.16.840.1.101.3.4.2.3";

	/** OID do Attribute do SignaturePolicyIdentifier (id-aa-ets-sigPolicyId). */
	private static final String ID_AA_ETS_SIG_POLICY_ID = "1.2.840.113549.1.9.16.5.1";

	private static final Policies POLICY = Policies.AD_RB_CADES_2_3;

	private static PrivateKey testPrivateKey;
	private static X509Certificate testCertificate;

	@BeforeClass
	public static void gerarCertificadoTeste() throws Exception {
		java.security.Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();
		testPrivateKey = keyPair.getPrivate();

		X500Name issuer = new X500Name("CN=Teste Integracao Hash Politica");
		BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
		Date notBefore = new Date(System.currentTimeMillis() - 86400000L);
		Date notAfter = new Date(System.currentTimeMillis() + 86400000L);

		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				issuer, serial, notBefore, notAfter, issuer, keyPair.getPublic());

		// SHA256withRSA no cert self-signed nao importa para o teste; o cenario do
		// bug e exercitado configurando o CAdESSigner com SHA512withRSA.
		ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider("BC").build(keyPair.getPrivate());

		testCertificate = new JcaX509CertificateConverter()
				.setProvider("BC")
				.getCertificate(certBuilder.build(contentSigner));
	}

	/**
	 * Le, por reflection, a {@link SignaturePolicy} interna do {@link CAdESSigner}
	 * (carregada pelo construtor via {@link PolicyFactory#loadPolicy(Policies)}).
	 */
	private SignaturePolicy getSignaturePolicy(CAdESSigner signer) throws Exception {
		Field f = CAdESSigner.class.getDeclaredField("signaturePolicy");
		f.setAccessible(true);
		return (SignaturePolicy) f.get(signer);
	}

	/**
	 * Injeta o certificado de teste para evitar NPE na validacao de tamanho de
	 * chave dentro de {@link CAdESSigner#prepareAlgAndLength()}.
	 */
	private void injectCertificate(CAdESSigner signer) throws Exception {
		Field certField = CAdESSigner.class.getDeclaredField("certificate");
		certField.setAccessible(true);
		certField.set(signer, testCertificate);
	}

	/**
	 * Monta o atributo {@code SignaturePolicyIdentifier} via {@link IdSigningPolicy}
	 * consumindo a {@link SignaturePolicy} fornecida, e retorna o {@link SignaturePolicyId}
	 * parseado.
	 */
	private SignaturePolicyId buildSignaturePolicyId(SignaturePolicy signaturePolicy, byte[] content)
			throws Exception {
		IdSigningPolicy idSigningPolicy = new IdSigningPolicy();
		idSigningPolicy.initialize(testPrivateKey, new Certificate[] { testCertificate }, content,
				signaturePolicy, content);

		Attribute attribute = idSigningPolicy.getValue();
		assertNotNull("O atributo SignaturePolicyIdentifier nao deve ser null", attribute);

		// O Attribute OID deve ser id-aa-ets-sigPolicyId
		assertEquals("O OID do atributo deve ser id-aa-ets-sigPolicyId",
				PKCSObjectIdentifiers.id_aa_ets_sigPolicyId, attribute.getAttrType());

		ASN1Encodable[] values = attribute.getAttrValues().toArray();
		assertEquals("O atributo deve ter exatamente 1 valor", 1, values.length);

		return SignaturePolicyId.getInstance(values[0]);
	}

	/**
	 * Teste principal: assinatura CAdES com SHA512withRSA + politica AD-RB (SHA-256).
	 *
	 * <p>Assere que:
	 * <ul>
	 *   <li>o atributo existe e tem 1 valor;</li>
	 *   <li>{@code hashAlgorithm} == SHA-256 (e NAO SHA-512), mesmo com algoritmo
	 *       de assinatura SHA512withRSA -> valida a correcao original (Req 2.2, 2.4);</li>
	 *   <li>{@code hashValue} (octets) == valor recalculado pela politica
	 *       ({@code computePolicyHash()}) E == {@code getValidatedPolicyHashOctetString()}
	 *       -> valida o recalculo/verificacao (Req 5.1, 5.2, 6.4).</li>
	 * </ul>
	 */
	@Test
	public void testSHA512withRSA_atributoUsaSHA256EHashRecalculado() throws Exception {
		byte[] content = "conteudo de teste para assinatura CAdES".getBytes("UTF-8");

		// 1) CAdESSigner com SHA512withRSA + politica real AD-RB CAdES 2.3.
		CAdESSigner signer = new CAdESSigner("SHA512withRSA", POLICY);
		injectCertificate(signer);

		SignaturePolicy signaturePolicy = getSignaturePolicy(signer);
		assertNotNull("SignaturePolicy carregada nao deve ser null", signaturePolicy);

		// Pre-condicao: a politica AD-RB define signPolicyHashAlg = SHA-256.
		String policyHashAlgOid = signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue();
		assertEquals("Pre-condicao: signPolicyHashAlg da politica AD-RB deve ser SHA-256",
				SHA256_OID, policyHashAlgOid);

		// 2) Exercita o cenario do bug: prepareAlgAndLength() com SHA512withRSA.
		//    Apos a correcao, signPolicyHashAlg deve permanecer SHA-256.
		signer.prepareAlgAndLength();

		assertEquals("Apos prepareAlgAndLength() com SHA512withRSA, signPolicyHashAlg deve "
				+ "permanecer SHA-256 (nao pode virar SHA-512)",
				SHA256_OID, signaturePolicy.getSignPolicyHashAlg().getAlgorithm().getValue());

		// 3) Monta o atributo SignaturePolicyIdentifier via IdSigningPolicy.
		SignaturePolicyId signaturePolicyId = buildSignaturePolicyId(signaturePolicy, content);

		OtherHashAlgAndValue sigPolicyHash = signaturePolicyId.getSigPolicyHash();
		assertNotNull("sigPolicyHash nao deve ser null", sigPolicyHash);

		// --- Assercao 1: hashAlgorithm == SHA-256 (NAO SHA-512) ---
		ASN1ObjectIdentifier hashAlgorithmOid = sigPolicyHash.getHashAlgorithm().getAlgorithm();
		logger.info("hashAlgorithm do atributo = {}", hashAlgorithmOid.getId());
		assertEquals("hashAlgorithm do sigPolicyHash deve ser SHA-256 (2.16.840.1.101.3.4.2.1), "
				+ "mesmo com algoritmo de assinatura SHA512withRSA. Se for SHA-512 "
				+ "(" + SHA512_OID + "), a correcao de signPolicyHashAlg regrediu.",
				SHA256_OID, hashAlgorithmOid.getId());

		// --- Assercao 2: hashValue == hash recalculado == valor validado ---
		byte[] attributeHashValue = sigPolicyHash.getHashValue().getOctets();

		byte[] recomputedHash = signaturePolicy.computePolicyHash();
		ASN1OctetString validated = signaturePolicy.getValidatedPolicyHashOctetString();
		assertNotNull("getValidatedPolicyHashOctetString() nao deve ser null para politica real", validated);
		byte[] validatedHash = validated.getOctets();

		logger.info("hashValue (atributo)   = {}", toHex(attributeHashValue));
		logger.info("computePolicyHash()    = {}", toHex(recomputedHash));
		logger.info("validatedPolicyHash()  = {}", toHex(validatedHash));

		// O valor do atributo deve ser exatamente o valor validado (o que o
		// IdSigningPolicy consome) e, como a politica real bate, o recalculado.
		assertArrayEquals("hashValue do atributo deve ser igual ao valor validado "
				+ "(getValidatedPolicyHashOctetString)",
				validatedHash, attributeHashValue);

		assertArrayEquals("hashValue do atributo deve ser igual ao hash recalculado "
				+ "pela politica (computePolicyHash) para AD-RB (o recalculo bate com o .der)",
				recomputedHash, attributeHashValue);

		assertArrayEquals("valor validado deve ser igual ao recalculado (recalculo bate com o .der)",
				recomputedHash, validatedHash);
	}

	/**
	 * Verifica que o hashValue do atributo tambem bate com o valor do .der
	 * (getSignPolicyHash().getDerOctetString()), confirmando que o recalculo
	 * reproduz o valor oficial da politica AD-RB.
	 *
	 * <p><b>Validates: Requirements 5.2, 6.4</b>
	 */
	@Test
	public void testHashValueBateComValorDoDer() throws Exception {
		byte[] content = "outro conteudo".getBytes("UTF-8");

		CAdESSigner signer = new CAdESSigner("SHA512withRSA", POLICY);
		injectCertificate(signer);
		SignaturePolicy signaturePolicy = getSignaturePolicy(signer);
		signer.prepareAlgAndLength();

		SignaturePolicyId signaturePolicyId = buildSignaturePolicyId(signaturePolicy, content);
		byte[] attributeHashValue = signaturePolicyId.getSigPolicyHash().getHashValue().getOctets();

		byte[] derHash = signaturePolicy.getSignPolicyHash().getDerOctetString().getOctets();

		logger.info("hashValue (atributo) = {}", toHex(attributeHashValue));
		logger.info("Der_Hash (.der)      = {}", toHex(derHash));

		// Para AD-RB o recalculo bate com o .der, entao o valor entregue tambem bate.
		assertArrayEquals("Para AD-RB, o hashValue do atributo deve bater com o signPolicyHash do .der",
				derHash, attributeHashValue);
	}

	/**
	 * Confirma que o {@code sigPolicyId} (OID da politica) e o
	 * {@code sigPolicyQualifiers} (URI) permanecem corretamente montados no
	 * atributo - apenas o octet string do hash passa pela logica de recalculo.
	 *
	 * <p><b>Validates: Requirements 6.4</b>
	 */
	@Test
	public void testDemaisCamposDoAtributoPreservados() throws Exception {
		byte[] content = "verificacao de campos".getBytes("UTF-8");

		CAdESSigner signer = new CAdESSigner("SHA512withRSA", POLICY);
		injectCertificate(signer);
		SignaturePolicy signaturePolicy = getSignaturePolicy(signer);
		signer.prepareAlgAndLength();

		SignaturePolicyId signaturePolicyId = buildSignaturePolicyId(signaturePolicy, content);

		// sigPolicyId == OID da politica
		String expectedPolicyOid = signaturePolicy.getSignPolicyInfo().getSignPolicyIdentifier().getValue();
		assertEquals("sigPolicyId deve ser o OID da politica",
				expectedPolicyOid, signaturePolicyId.getSigPolicyId().getId());

		// sigPolicyQualifiers deve conter o qualifierId id-spq-ets-uri (1.2.840.113549.1.9.16.5.1)
		assertNotNull("sigPolicyQualifiers nao deve ser null", signaturePolicyId.getSigPolicyQualifiers());
		assertEquals("Deve haver 1 qualifier", 1,
				signaturePolicyId.getSigPolicyQualifiers().size());
		assertEquals("O qualifierId deve ser id-spq-ets-uri",
				ID_AA_ETS_SIG_POLICY_ID,
				signaturePolicyId.getSigPolicyQualifiers().getInfoAt(0).getSigPolicyQualifierId().getId());
	}

	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
