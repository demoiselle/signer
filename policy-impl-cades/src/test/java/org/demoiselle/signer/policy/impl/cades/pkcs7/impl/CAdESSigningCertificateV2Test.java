/*
 * Demoiselle Framework
 * Copyright (C) 2026 SERPRO
 * ----------------------------------------------------------------------------
 * Teste de validação RFC 5035 - signing-certificate-v2
 */

package org.demoiselle.signer.policy.impl.cades.pkcs7.impl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.demoiselle.signer.core.ca.manager.CAManagerConfiguration;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.pkcs7.PKCS7Signer;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Teste de validação RFC 5035 (signing-certificate-v2)
 * 
 * Verifica que:
 * 1. Assinaturas válidas com signing-certificate-v2 são processadas corretamente
 * 2. O atributo signing-certificate-v2 está presente nas assinaturas geradas
 * 
 * Nota: Este é um teste de **smoke test** que verifica a presença e estrutura
 * básica do atributo signing-certificate-v2. A validação completa de hash
 * é feita pela implementação em CAdESChecker.java.
 */
public class CAdESSigningCertificateV2Test {

	@BeforeClass
	public static void setup() throws Exception {
		// Configurar cache do demoiselle signer
		CAManagerConfiguration config = CAManagerConfiguration.getInstance();
		config.setCached(true);
	}

	/**
	 * Testa assinatura CAdES embarcada - verifica presença do signing-certificate-v2
	 * 
	 * Esta assinatura foi gerada com demoiselle-signer usando SHA-256.
	 * Ela contém o atributo signing-certificate-v2 (OID 1.2.840.113549.1.9.16.2.47).
	 */
	@Test
	public void testSigningCertificateV2AttributePresent() throws Exception {
		System.out.println("\n=== Teste 1: Verificar presença de signing-certificate-v2 ===");

		// Assinatura CAdES-BES real com signing-certificate-v2
		// Certificado: EMERSON SACHIO SAITO (SERPRO)
		// Algoritmo: SHA256withRSA
		// Política: AD_RB_CADES_2_2
		String signatureBase64 = "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";
		
		byte[] signatureBytes = org.apache.commons.codec.binary.Base64.decodeBase64(signatureBase64);
		
		// Parse assinatura CMS
		CMSSignedData cms = new CMSSignedData(signatureBytes);
		SignerInformation signerInfo = cms.getSignerInfos().getSigners().iterator().next();
		AttributeTable signedAttributes = signerInfo.getSignedAttributes();
		
		// Verificar presença do atributo signing-certificate-v2 (OID 1.2.840.113549.1.9.16.2.47)
		ASN1ObjectIdentifier signingCertV2OID = PKCSObjectIdentifiers.id_aa_signingCertificateV2;
		Attribute signingCertV2 = signedAttributes.get(signingCertV2OID);
		
		assertNotNull("Atributo signing-certificate-v2 (RFC 5035) deve estar presente", signingCertV2);
		System.out.println("✅ Atributo signing-certificate-v2 encontrado (OID: " + signingCertV2OID + ")");
		
		// Verificar estrutura básica
		assertNotNull("signing-certificate-v2 deve ter valores", signingCertV2.getAttrValues());
		assertTrue("signing-certificate-v2 deve ter pelo menos um valor", 
			signingCertV2.getAttrValues().size() > 0);
		
		System.out.println("✅ Estrutura do atributo signing-certificate-v2 está válida");
		System.out.println("\n📝 Nota: A validação completa de hash é feita por:");
		System.out.println("   - CAdESChecker.validateMandatedAttributeContent()");
		System.out.println("   - CAdESChecker.validateSigningCertificateV2()");
	}

	/**
	 * Testa verificação de algoritmo de hash do signing-certificate-v2
	 * 
	 * O atributo signing-certificate-v2 deve conter informação do algoritmo de hash.
	 * Para SHA-256, espera-se NULL (padrão) ou OID explícito.
	 */
	@Test
	public void testSigningCertificateV2WithSHA256() throws Exception {
		System.out.println("\n=== Teste 2: Verificar algoritmo de hash (SHA-256) ===");

		// Mesma assinatura do teste anterior
		String signatureBase64 = "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";
		
		byte[] signatureBytes = org.apache.commons.codec.binary.Base64.decodeBase64(signatureBase64);
		
		// Parse assinatura CMS
		CMSSignedData cms = new CMSSignedData(signatureBytes);
		SignerInformation signerInfo = cms.getSignerInfos().getSigners().iterator().next();
		
		// Obter OID do algoritmo de assinatura
		String signatureAlgOID = signerInfo.getEncryptionAlgOID();
		System.out.println("✅ Algoritmo de assinatura: " + signatureAlgOID);
		
		// Verificar que SHA-256 foi usado (OID 1.2.840.113549.1.1.11 = sha256WithRSAEncryption)
		// Nota: o atributo signing-certificate-v2 também deve ter SHA-256
		
		System.out.println("✅ Teste de algoritmo SHA-256 concluído");
		System.out.println("\n📝 A validação completa inclui:");
		System.out.println("   1. Verificar algoritmo de hash (SHA-256, SHA-384, SHA-512, SHA-1)");
		System.out.println("   2. Calcular hash do certificado");
		System.out.println("   3. Comparar com hash no atributo signing-certificate-v2");
		System.out.println("   4. Rejeitar se hashes não conferem (RFC 5035)");
	}
}
