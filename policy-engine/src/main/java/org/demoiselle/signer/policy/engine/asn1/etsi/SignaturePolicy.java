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

import java.security.MessageDigest;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.demoiselle.signer.policy.engine.asn1.ASN1Object;
import org.demoiselle.signer.policy.engine.util.MessagesBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In this structure the policy information is preceded by
 * an identifier for the hashing algorithm used to protect
 * the signature policy and followed by the hash value which
 * shall be re-calculated and checked whenever the policy is
 * passed between the issuer and signer/verifier. The hash is
 * calculated without the outer type and length fields.
 *
 * <pre>
 * SignaturePolicy ::= SEQUENCE {
 *     signPolicyHashAlg AlgorithmIdentifier,
 *     signPolicyInfo SignPolicyInfo,
 *     signPolicyHash SignPolicyHash OPTIONAL
 * }
 * </pre>
 *
 * @see ASN1Primitive
 * @see ASN1Sequence
 * @see DEROctetString
 */
public class SignaturePolicy {

	private AlgorithmIdentifier signPolicyHashAlg;
	private SignPolicyInfo signPolicyInfo;
	private SignPolicyHash signPolicyHash;
	private String signPolicyURI;

	/**
	 * OID do algoritmo de hash usado para assinatura do documento.
	 * Preenchido pelo CAdESSigner com base no algoritmo de assinatura selecionado
	 * (ex: SHA512withRSA -> OID SHA-512 = 2.16.840.1.101.3.4.2.3).
	 * Diferente de signPolicyHashAlg que eh o algoritmo do hash do arquivo .der da politica.
	 */
	private String signatureAlgorithmHashOID;
	private static MessagesBundle policyMessagesBundle = new MessagesBundle("messages_policy");
	private static final Logger logger = LoggerFactory.getLogger(SignaturePolicy.class);

	/**
	 * Primitivos DER originais dos dois primeiros elementos da SEQUENCE
	 * {@code SignaturePolicy} ({@code signPolicyHashAlg} e {@code signPolicyInfo}),
	 * capturados em {@link #parse(ASN1Primitive)}. Sao necessarios para reconstruir
	 * a SEQUENCE sem o campo {@code signPolicyHash} e recalcular o hash da politica
	 * conforme a regra ETSI. Marcados como {@code transient} por nao fazerem parte
	 * do estado serializavel logico da classe.
	 */
	private transient ASN1Encodable signPolicyHashAlgPrimitive;
	private transient ASN1Encodable signPolicyInfoPrimitive;

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

	public String getSignPolicyURI() {
		return signPolicyURI;
	}

	public void setSignPolicyURI(String signPolicyURI) {
		this.signPolicyURI = signPolicyURI;
	}

	public String getSignatureAlgorithmHashOID() {
		return signatureAlgorithmHashOID;
	}

	public void setSignatureAlgorithmHashOID(String signatureAlgorithmHashOID) {
		this.signatureAlgorithmHashOID = signatureAlgorithmHashOID;
	}

	public void parse(ASN1Primitive derObject) {
		ASN1Sequence derSequence = ASN1Object.getDERSequence(derObject);
		// Guarda os primitivos DER originais de signPolicyHashAlg (indice 0) e
		// signPolicyInfo (indice 1) para permitir o recalculo posterior do hash
		// da politica (regra ETSI) reconstruindo a SEQUENCE sem o signPolicyHash.
		this.signPolicyHashAlgPrimitive = derSequence.getObjectAt(0);
		this.signPolicyInfoPrimitive = derSequence.getObjectAt(1);
		this.signPolicyHashAlg = new AlgorithmIdentifier();
		this.signPolicyHashAlg.parse(derSequence.getObjectAt(0).toASN1Primitive());
		this.signPolicyInfo = new SignPolicyInfo();
		this.signPolicyInfo.parse(derSequence.getObjectAt(1).toASN1Primitive());
		if (derSequence.size() == 3) {
			this.signPolicyHash = new SignPolicyHash(ASN1OctetString.getInstance(derSequence.getObjectAt(2)));
		}
	}

	/**
	 * Mapeia o OID do algoritmo de hash (conforme {@code signPolicyHashAlg}) para
	 * o nome de algoritmo aceito por {@link java.security.MessageDigest}.
	 *
	 * @param oid o OID do algoritmo de hash
	 * @return o nome do algoritmo (ex: "SHA-256"), ou {@code null} para OID
	 *         desconhecido/nao mapeavel.
	 */
	private String oidToDigestName(String oid) {
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
	 * Extrai o "conteudo" (value) de um encoding DER TLV, removendo os octetos
	 * externos de tipo (tag) e de comprimento (length). Retorna apenas os bytes
	 * de valor (V) da estrutura.
	 *
	 * <p>Trata tanto a forma curta (short form, 1 octeto de length) quanto a forma
	 * longa (long form, {@code 0x80 | numeroDeOctetos}).
	 *
	 * @param der o encoding DER completo (TLV)
	 * @return apenas o conteudo (value), sem tag nem length externos
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

	/**
	 * Recalcula o hash da politica conforme a regra ETSI.
	 *
	 * <p>Reconstroi a SEQUENCE {@code { signPolicyHashAlg, signPolicyInfo }}
	 * (excluindo o campo {@code signPolicyHash}) e aplica o digest sobre o
	 * <b>conteudo</b> dessa SEQUENCE, ou seja, "without the outer type and length
	 * fields" (sem os octetos externos de tipo/comprimento), exatamente como
	 * descrito no comentario de cabecalho desta classe.
	 *
	 * <p><b>Variante ETSI adotada</b>: esta e a variante confirmada empiricamente
	 * na task 5 contra as politicas ICP-Brasil reais (AD-RB/AD-RT/AD-RV/AD-RC/AD-RA),
	 * onde o digest do conteudo da SEQUENCE reconstruida (sem o header externo)
	 * reproduz exatamente o {@code signPolicyHash} presente no arquivo .der. O
	 * algoritmo de digest utilizado e o indicado por {@code signPolicyHashAlg}.
	 *
	 * @return os bytes do digest recalculado (Recomputed_Hash)
	 * @throws Exception se o algoritmo for desconhecido/indisponivel ou se ocorrer
	 *                   qualquer erro na reconstrucao/codificacao DER
	 */
	public byte[] computePolicyHash() throws Exception {
		String digestName = oidToDigestName(this.signPolicyHashAlg.getAlgorithm().getValue());
		if (digestName == null) {
			throw new java.security.NoSuchAlgorithmException(
					"algoritmo de hash da politica desconhecido: "
							+ this.signPolicyHashAlg.getAlgorithm().getValue());
		}
		DERSequence seqToHash = new DERSequence(
				new ASN1Encodable[] { this.signPolicyHashAlgPrimitive, this.signPolicyInfoPrimitive });
		byte[] seqDer = seqToHash.getEncoded("DER");
		byte[] content = stripOuterTypeAndLength(seqDer);
		MessageDigest md = MessageDigest.getInstance(digestName);
		return md.digest(content);
	}

	/**
	 * Retorna o octet string do hash da politica a ser usado no atributo
	 * {@code SignaturePolicyIdentifier}, aplicando a logica de recalculo,
	 * comparacao e fallback seguro.
	 *
	 * <ul>
	 *   <li>Se o algoritmo de {@code signPolicyHashAlg} for desconhecido/nao
	 *       mapeavel: loga um WARNING e retorna o valor original do .der (fallback).</li>
	 *   <li>Se o valor recalculado ({@link #computePolicyHash()}) for igual ao
	 *       {@code signPolicyHash} do .der: retorna o valor RECALCULADO.</li>
	 *   <li>Se divergir: loga um WARNING e retorna o valor do .der (fallback).</li>
	 *   <li>Qualquer excecao durante o processo: loga um WARNING e retorna o valor
	 *       do .der (fallback). NUNCA propaga excecao.</li>
	 * </ul>
	 *
	 * <p>Se {@code signPolicyHash} for {@code null} (campo OPTIONAL ausente), nao ha
	 * valor do .der para fallback; nesse caso o metodo loga um WARNING e retorna
	 * {@code null}, sem lancar excecao.
	 *
	 * @return o {@link ASN1OctetString} validado (recalculado ou fallback do .der),
	 *         ou {@code null} se nao houver {@code signPolicyHash} disponivel.
	 */
	public ASN1OctetString getValidatedPolicyHashOctetString() {
		try {
			if (this.signPolicyHash == null) {
				logger.warn("signPolicyHash ausente na politica; nao ha valor do .der para usar");
				return null;
			}

			String digestName = oidToDigestName(this.signPolicyHashAlg.getAlgorithm().getValue());
			if (digestName == null) {
				logger.warn("algoritmo de hash da politica desconhecido; usando valor do .der");
				return this.signPolicyHash.getDerOctetString();
			}

			byte[] recomputed = computePolicyHash();
			byte[] der = this.signPolicyHash.getDerOctetString().getOctets();

			if (Arrays.equals(recomputed, der)) {
				logger.info("hash recalculado da politica igual ao valor do .der; usando valor recalculado");
				return new DEROctetString(recomputed);
			}

			logger.warn("hash recalculado da politica difere do valor do .der; usando valor do .der");
			return this.signPolicyHash.getDerOctetString();
		} catch (Throwable t) {
			logger.warn("falha ao recalcular hash da politica; usando valor do .der", t);
			try {
				if (this.signPolicyHash != null) {
					return this.signPolicyHash.getDerOctetString();
				}
			} catch (Throwable ignored) {
				// nada a fazer: sem fallback disponivel
			}
			return null;
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(policyMessagesBundle.getString("text.uri")).append(this.getSignPolicyURI()).append("\n");
		builder.append(policyMessagesBundle.getString("text.algo.hash")).append(this.getSignPolicyHashAlg().getAlgorithm().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.hash")).append(this.getSignPolicyHash().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.oid")).append(this.getSignPolicyInfo().getSignPolicyIdentifier().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.launch.date")).append(this.getSignPolicyInfo().getDateOfIssue().getDate()).append("\n");
		builder.append(policyMessagesBundle.getString("text.issuer")).append(this.getSignPolicyInfo().getPolicyIssuerName()).append("\n");
		builder.append(policyMessagesBundle.getString("text.application")).append(this.getSignPolicyInfo().getFieldOfApplication().getValue()).append("\n");
		builder.append(policyMessagesBundle.getString("text.valid")).append(this.getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod()).append("\n");
		SignerAndVerifierRules signerAndVerifierRules = this.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules().getSignerAndVeriferRules();
		if (signerAndVerifierRules != null && signerAndVerifierRules.getSignerRules() != null) {
			builder.append(policyMessagesBundle.getString("text.external")).append(signerAndVerifierRules.getSignerRules().getExternalSignedData()).append("\n");
			builder.append(policyMessagesBundle.getString("text.mandated.ref")).append(signerAndVerifierRules.getSignerRules().getMandatedCertificateRef()).append("\n");
			builder.append(policyMessagesBundle.getString("text.mandated.info")).append(signerAndVerifierRules.getSignerRules().getMandatedCertificateInfo()).append("\n");
		}

		AlgorithmConstraintSet algorithmConstraintSet = this.getSignPolicyInfo().getSignatureValidationPolicy()
				.getCommonRules().getAlgorithmConstraintSet();
		if (algorithmConstraintSet != null && algorithmConstraintSet.getSignerAlgorithmConstraints() != null) {
			for (AlgAndLength oi : algorithmConstraintSet.getSignerAlgorithmConstraints().getAlgAndLengths()) {
				builder.append(policyMessagesBundle.getString("text.algo")).append(oi.getAlgID()).append("\n");
				builder.append(policyMessagesBundle.getString("text.key.min.size")).append(oi.getMinKeyLength()).append("\n");
			}
		}

		if (signerAndVerifierRules != null && signerAndVerifierRules.getSignerRules() != null) {
			builder.append("==============================================================").append("\n");
			if (signerAndVerifierRules.getSignerRules().getMandatedSignedAttr().getObjectIdentifiers() != null) {
				for (ObjectIdentifier oi : signerAndVerifierRules.getSignerRules().getMandatedSignedAttr().getObjectIdentifiers()) {
					builder.append(policyMessagesBundle.getString("text.signed.attr.oid")).append(oi.getValue()).append("\n");
				}
			}

			builder.append("==============================================================").append("\n");
			if (signerAndVerifierRules.getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
				for (ObjectIdentifier oi : signerAndVerifierRules.getSignerRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
					builder.append(policyMessagesBundle.getString("text.unsigned.attr.oid")).append(oi.getValue()).append("\n");
				}
			}

			if (signerAndVerifierRules.getVerifierRules() != null
					&& signerAndVerifierRules.getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers() != null) {
				builder.append("==============================================================").append("\n");
				for (ObjectIdentifier oi : signerAndVerifierRules.getVerifierRules().getMandatedUnsignedAttr().getObjectIdentifiers()) {
					builder.append(policyMessagesBundle.getString("text.unsigned.attr.oid")).append(oi.getValue()).append("\n");
				}
			}
		}

		return builder.toString();
	}
}
