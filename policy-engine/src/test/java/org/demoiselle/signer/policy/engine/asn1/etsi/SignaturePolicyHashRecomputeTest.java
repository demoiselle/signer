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

package org.demoiselle.signer.policy.engine.asn1.etsi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * EXPLORATION / DISCOVERY TEST (Task 5).
 *
 * <p>Objetivo: determinar empiricamente qual variante de calculo do hash da
 * politica ICP-Brasil bate com o {@code signPolicyHash} presente no arquivo
 * .der. A estrutura ASN.1 e:
 *
 * <pre>
 * SignaturePolicy ::= SEQUENCE {
 *     signPolicyHashAlg AlgorithmIdentifier,
 *     signPolicyInfo    SignPolicyInfo,
 *     signPolicyHash    SignPolicyHash OPTIONAL
 * }
 * </pre>
 *
 * <p>O comentario de cabecalho da classe {@link SignaturePolicy} diz que o hash
 * "is calculated without the outer type and length fields", sobre a estrutura
 * excluindo o proprio {@code signPolicyHash}.
 *
 * <p>IMPORTANTE: como {@code SignaturePolicy.computePolicyHash()} ainda NAO
 * existe (isso e a task 7), este teste replica a logica candidata DENTRO do
 * proprio teste, usando BouncyCastle ASN.1 + {@link MessageDigest}, para
 * descobrir qual variante bate. NAO implementa nada em SignaturePolicy.
 *
 * <p>Variantes testadas contra {@code getObjectAt(2)} (o signPolicyHash do .der):
 * <ul>
 *   <li><b>A</b>: digest sobre o encoding DER da SEQUENCE reconstruida
 *       {@code {getObjectAt(0), getObjectAt(1)}} (COM header da SEQUENCE).</li>
 *   <li><b>B</b>: digest sobre a concatenacao do conteudo interno dos dois
 *       elementos SEM o header da SEQUENCE externa (regra "without the outer
 *       type and length fields").</li>
 *   <li><b>C</b> (documentacao): digest sobre o arquivo .der inteiro.</li>
 *   <li><b>D</b> (documentacao): digest sobre a SEQUENCE completa incluindo
 *       signPolicyHash.</li>
 *   <li><b>E</b>: digest sobre a concatenacao dos encodings DER individuais de
 *       cada elemento (getObjectAt(0).getEncoded + getObjectAt(1).getEncoded)
 *       -- variante equivalente ao "conteudo" da SEQUENCE com headers internos.</li>
 * </ul>
 */
public class SignaturePolicyHashRecomputeTest {

	private static final Logger logger = LoggerFactory.getLogger(SignaturePolicyHashRecomputeTest.class);

	// OIDs de algoritmo de hash -> nome MessageDigest
	private static String oidToDigestName(String oid) {
		if (oid == null) {
			return null;
		}
		switch (oid) {
			case "2.16.840.1.101.3.4.2.1":
				return "SHA-256";
			case "2.16.840.1.101.3.4.2.2":
				return "SHA-384";
			case "2.16.840.1.101.3.4.2.3":
				return "SHA-512";
			case "1.3.14.3.2.26":
				return "SHA-1";
			default:
				return null;
		}
	}

	/**
	 * Politicas CAdES reais para explorar. Comeca por PA_AD_RB (requisito da task)
	 * e cobre AD-RB/AD-RT/AD-RV/AD-RC/AD-RA.
	 */
	private static final Policies[] POLICIES_TO_EXPLORE = new Policies[] {
			Policies.AD_RB_CADES_2_3,
			Policies.AD_RB_CADES_2_4,
			Policies.AD_RT_CADES_2_3,
			Policies.AD_RV_CADES_2_3,
			Policies.AD_RC_CADES_2_3,
			Policies.AD_RA_CADES_2_4,
	};

	private byte[] readResource(String path) throws Exception {
		try (InputStream is = getClass().getResourceAsStream(path)) {
			assertNotNull("resource nao encontrado: " + path, is);
			return org.apache.commons.io.IOUtils.toByteArray(is);
		}
	}

	private byte[] digest(String digestName, byte[] data) throws Exception {
		MessageDigest md = MessageDigest.getInstance(digestName);
		return md.digest(data);
	}

	/**
	 * Extrai o "conteudo" (value) de um encoding DER TLV, removendo os octetos
	 * externos de type e length. Retorna apenas os V (value) bytes.
	 */
	private byte[] stripOuterTypeAndLength(byte[] der) {
		// byte 0 = tag; a partir do byte 1 vem o length (short ou long form)
		int idx = 1;
		int first = der[idx] & 0xFF;
		int lengthOctets;
		if ((first & 0x80) == 0) {
			// short form: 1 octeto de length
			lengthOctets = 1;
		} else {
			// long form: 0x80 | numero de octetos de length
			int numLenOctets = first & 0x7F;
			lengthOctets = 1 + numLenOctets;
		}
		int contentStart = 1 + lengthOctets;
		return Arrays.copyOfRange(der, contentStart, der.length);
	}

	@Test
	public void discoverEtsiHashVariant() throws Exception {
		logger.info("==================================================================");
		logger.info(" EXPLORACAO: recalculo do hash da politica (task 5)");
		logger.info("==================================================================");

		// Contagem de matches por variante ao longo de todas as politicas.
		Map<String, Integer> variantMatchCount = new LinkedHashMap<>();
		String[] variantNames = { "A_seqWithHeader", "B_seqWithoutHeader", "C_fullDer", "D_seqWithHash", "E_concatElements" };
		for (String v : variantNames) {
			variantMatchCount.put(v, 0);
		}

		boolean paAdRbAsserted = false;
		String paAdRbWinningVariant = null;

		for (Policies policy : POLICIES_TO_EXPLORE) {
			String path = policy.getFile();
			logger.info("------------------------------------------------------------------");
			logger.info("Politica: {} ({})", policy.name(), path);

			// Carrega via o mesmo caminho de PolicyFactory.loadPolicy para obter o
			// SignaturePolicy parseado (algoritmo + valor esperado do hash).
			PolicyFactory factory = PolicyFactory.getInstance();
			SignaturePolicy sp = factory.loadPolicy(policy);

			String hashAlgOid = sp.getSignPolicyHashAlg().getAlgorithm().getValue();
			String digestName = oidToDigestName(hashAlgOid);
			logger.info("  signPolicyHashAlg OID = {} -> {}", hashAlgOid, digestName);

			if (sp.getSignPolicyHash() == null) {
				logger.warn("  politica NAO possui signPolicyHash (campo OPTIONAL ausente); pulando");
				continue;
			}
			byte[] expected = sp.getSignPolicyHash().getDerOctetString().getOctets();
			logger.info("  signPolicyHash esperado ({} bytes) = {}", expected.length, toHex(expected));

			if (digestName == null) {
				logger.warn("  algoritmo de hash desconhecido; nao da para recalcular. Pulando politica.");
				continue;
			}

			// Le os bytes DER originais do resource e parseia a SEQUENCE completa.
			byte[] fullDer = readResource(path);
			ASN1Primitive primitive;
			try (ASN1InputStream ais = new ASN1InputStream(fullDer)) {
				primitive = ais.readObject();
			}
			ASN1Sequence seq = ASN1Sequence.getInstance(primitive);
			ASN1Encodable e0 = seq.getObjectAt(0); // signPolicyHashAlg
			ASN1Encodable e1 = seq.getObjectAt(1); // signPolicyInfo

			// -------- Variante A: SEQUENCE reconstruida {e0, e1}, encoding DER completo (COM header) --------
			byte[] seqReconstructed = new DERSequence(new ASN1Encodable[] { e0, e1 }).getEncoded("DER");
			byte[] varA = digest(digestName, seqReconstructed);

			// -------- Variante B: SEQUENCE reconstruida SEM os octetos externos de type/length --------
			byte[] seqContentOnly = stripOuterTypeAndLength(seqReconstructed);
			byte[] varB = digest(digestName, seqContentOnly);

			// -------- Variante C: arquivo .der inteiro (apenas documentacao do que NAO bate) --------
			byte[] varC = digest(digestName, fullDer);

			// -------- Variante D: SEQUENCE completa incluindo signPolicyHash (documentacao) --------
			byte[] seqWithHash = seq.getEncoded("DER");
			byte[] varD = digest(digestName, seqWithHash);

			// -------- Variante E: concatenacao dos encodings DER individuais de e0 e e1 --------
			byte[] enc0 = e0.toASN1Primitive().getEncoded("DER");
			byte[] enc1 = e1.toASN1Primitive().getEncoded("DER");
			byte[] concat = new byte[enc0.length + enc1.length];
			System.arraycopy(enc0, 0, concat, 0, enc0.length);
			System.arraycopy(enc1, 0, concat, enc0.length, enc1.length);
			byte[] varE = digest(digestName, concat);

			logMatch(policy, "A_seqWithHeader", varA, expected, variantMatchCount);
			logMatch(policy, "B_seqWithoutHeader", varB, expected, variantMatchCount);
			logMatch(policy, "C_fullDer", varC, expected, variantMatchCount);
			logMatch(policy, "D_seqWithHash", varD, expected, variantMatchCount);
			logMatch(policy, "E_concatElements", varE, expected, variantMatchCount);

			// Registra a variante vencedora para PA_AD_RB.
			if (policy.name().startsWith("AD_RB")) {
				if (Arrays.equals(varA, expected)) {
					paAdRbWinningVariant = "A_seqWithHeader";
				} else if (Arrays.equals(varB, expected)) {
					paAdRbWinningVariant = "B_seqWithoutHeader";
				} else if (Arrays.equals(varC, expected)) {
					paAdRbWinningVariant = "C_fullDer";
				} else if (Arrays.equals(varD, expected)) {
					paAdRbWinningVariant = "D_seqWithHash";
				} else if (Arrays.equals(varE, expected)) {
					paAdRbWinningVariant = "E_concatElements";
				}
				if (paAdRbWinningVariant != null) {
					paAdRbAsserted = true;
				}
			}
		}

		logger.info("==================================================================");
		logger.info(" RESUMO DE MATCHES POR VARIANTE (sobre {} politicas):", POLICIES_TO_EXPLORE.length);
		for (Map.Entry<String, Integer> en : variantMatchCount.entrySet()) {
			logger.info("   {} -> {} match(es)", en.getKey(), en.getValue());
		}
		logger.info("==================================================================");

		// Determina a variante vencedora global (a que mais bate).
		String globalWinner = null;
		int best = 0;
		for (Map.Entry<String, Integer> en : variantMatchCount.entrySet()) {
			if (en.getValue() > best) {
				best = en.getValue();
				globalWinner = en.getKey();
			}
		}

		// Espelha o resumo em System.out para garantir captura no relatorio surefire.
		System.out.println("=== RESUMO EXPLORACAO HASH POLITICA (task 5) ===");
		for (Map.Entry<String, Integer> en : variantMatchCount.entrySet()) {
			System.out.println("   " + en.getKey() + " -> " + en.getValue() + " match(es)");
		}

		if (globalWinner != null && best > 0) {
			logger.info(" VARIANTE VENCEDORA: {} ({} match(es))", globalWinner, best);
			logger.info(" >>> A task 7 deve implementar SignaturePolicy.computePolicyHash() usando esta variante.");
			System.out.println(" VARIANTE VENCEDORA: " + globalWinner + " (" + best + " match(es))");
		} else {
			logger.error(" NENHUMA variante bateu com nenhuma politica real!");
			logger.error(" >>> ACHADO CRITICO: o recalculo do hash da politica nao reproduz o valor do .der.");
			logger.error(" >>> Na pratica a implementacao da task 7 sempre caira no fallback (valor do .der).");
			System.out.println(" NENHUMA variante bateu com nenhuma politica real (ACHADO CRITICO).");
		}
		System.out.println(" PA_AD_RB: variante que bateu = " + paAdRbWinningVariant);

		// =====================================================================
		// ASSERCAO PRINCIPAL (task 5): para PA_AD_RB, alguma variante bate.
		// =====================================================================
		// Se NENHUMA variante bater em nenhuma politica real, este teste FALHA de
		// proposito (achado critico) -- NAO forcamos passagem artificial.
		assertTrue(
				"ACHADO CRITICO: nenhuma variante de recalculo do hash da politica bateu com o "
						+ "signPolicyHash do .der para PA_AD_RB. O recalculo nao reproduz o valor oficial; "
						+ "na pratica a task 7 sempre usaria o fallback. Ver saida/log do teste para detalhes.",
				paAdRbAsserted);

		logger.info(" PA_AD_RB: variante que bateu = {}", paAdRbWinningVariant);

		// =====================================================================
		// RESULTADO CONFIRMADO EMPIRICAMENTE (executado contra as 6 politicas reais):
		//
		//   A_seqWithHeader     -> 0 matches
		//   B_seqWithoutHeader  -> 6 matches  (TODAS as politicas)
		//   C_fullDer           -> 0 matches
		//   D_seqWithHash       -> 0 matches
		//   E_concatElements    -> 6 matches  (TODAS as politicas)
		//
		// >>> VARIANTE ETSI CORRETA: B_seqWithoutHeader <<<
		//   digest( conteudo da SEQUENCE { signPolicyHashAlg, signPolicyInfo }
		//           SEM os octetos externos de type/length da SEQUENCE ),
		//   usando o algoritmo indicado por signPolicyHashAlg.
		//
		// NOTA: a variante E (concatenacao dos encodings DER de cada elemento)
		// produz EXATAMENTE o mesmo input de digest que a B, porque o "conteudo"
		// (value) de uma SEQUENCE DER e, por definicao, a concatenacao dos
		// encodings TLV de seus elementos. Portanto B e E sao equivalentes; B e a
		// formulacao canonica que corresponde a regra ETSI citada no cabecalho da
		// classe SignaturePolicy ("The hash is calculated without the outer type
		// and length fields").
		//
		// >>> A task 7 (SignaturePolicy.computePolicyHash()) DEVE usar a variante B. <<<
		// =====================================================================
		org.junit.Assert.assertEquals(
				"A variante ETSI confirmada para PA_AD_RB deve ser B_seqWithoutHeader "
						+ "(digest do conteudo da SEQUENCE {signPolicyHashAlg, signPolicyInfo} sem o header externo). "
						+ "Esta e a variante que a task 7 deve implementar.",
				"B_seqWithoutHeader", paAdRbWinningVariant);
	}

	private void logMatch(Policies policy, String variant, byte[] computed, byte[] expected,
			Map<String, Integer> counter) {
		boolean match = Arrays.equals(computed, expected);
		logger.info("  [{}] variante {} -> {} ({} bytes){}",
				policy.name(), variant, match ? "BATEU" : "nao bate", computed.length,
				match ? "" : "  computed=" + toHex(computed));
		if (match) {
			counter.put(variant, counter.get(variant) + 1);
			System.out.println("  [" + policy.name() + "] variante " + variant + " -> BATEU");
		}
	}

	private static String toHex(byte[] data) {
		StringBuilder sb = new StringBuilder();
		for (byte b : data) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}
}
