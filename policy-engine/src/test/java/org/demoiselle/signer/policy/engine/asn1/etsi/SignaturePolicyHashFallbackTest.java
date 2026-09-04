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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory.Policies;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * PRESERVATION / SAFE-FALLBACK TEST (Task 6).
 *
 * <p>Valida a <b>Property 4 (Preservation)</b> do design: quando o recalculo do
 * hash da politica falha (algoritmo desconhecido/indisponivel, excecao) OU o
 * hash recalculado difere do {@code signPolicyHash} presente no .der, o metodo
 * {@code SignaturePolicy.getValidatedPolicyHashOctetString()} DEVE:
 * <ul>
 *   <li>retornar o valor ORIGINAL do .der ({@code getSignPolicyHash().getDerOctetString()});</li>
 *   <li>emitir um WARNING via logger;</li>
 *   <li>NUNCA lancar excecao que quebre a geracao da assinatura.</li>
 * </ul>
 * E, no caminho feliz (politica real onde o recalculo bate), o metodo deve
 * retornar o valor recalculado -- que, para as politicas ICP-Brasil reais,
 * coincide com o valor do .der (confirmado pela variante B da task 5).
 *
 * <p><b>Metodologia observation-first / abordagem (b) por reflection:</b>
 * O metodo {@code getValidatedPolicyHashOctetString()} AINDA NAO EXISTE em
 * {@link SignaturePolicy} (sera criado na task 7). Para que este arquivo de
 * teste COMPILE hoje sem quebrar o build do modulo, os testes invocam o metodo
 * por reflection. Enquanto o metodo nao existir, {@link #invokeValidated} lanca
 * um {@link AssertionError} com mensagem clara ("metodo ainda nao implementado
 * (task 7)"), fazendo os testes ficarem VERMELHOS ate a implementacao da task 7
 * -- exatamente o baseline esperado nesta fase. Depois da task 7 os mesmos
 * testes devem ficar VERDES sem qualquer alteracao aqui.
 *
 * <p>Escolhemos a opcao (b) (reflection) em vez de (a) (chamada direta que nao
 * compila) porque o modulo policy-engine nao possui um mecanismo pre-existente
 * para testes "esperado-nao-compilar", e manter o build de teste compilavel e
 * preferivel.
 */
public class SignaturePolicyHashFallbackTest {

	private static final Logger logger = LoggerFactory.getLogger(SignaturePolicyHashFallbackTest.class);

	private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";
	/** OID sintetico/nao-mapeavel para simular algoritmo de hash desconhecido. */
	private static final String OID_DESCONHECIDO = "1.2.3.4.5.6.7.8.9.0";

	/**
	 * Invoca {@code SignaturePolicy.getValidatedPolicyHashOctetString()} por
	 * reflection. Enquanto o metodo nao existir (pre-task-7), falha com mensagem
	 * clara para deixar o teste vermelho de forma controlada. Reencaminha
	 * qualquer excecao real lancada pelo metodo (para os testes que verificam
	 * "nunca lanca").
	 */
	private ASN1OctetString invokeValidated(SignaturePolicy sp) throws Throwable {
		Method m;
		try {
			m = SignaturePolicy.class.getMethod("getValidatedPolicyHashOctetString");
		} catch (NoSuchMethodException nsme) {
			fail("SignaturePolicy.getValidatedPolicyHashOctetString() ainda nao implementado (task 7). "
					+ "Este teste (task 6) fica vermelho de proposito ate a task 7 -- baseline observation-first.");
			return null; // inalcancavel
		}
		try {
			Object result = m.invoke(sp);
			return (ASN1OctetString) result;
		} catch (InvocationTargetException ite) {
			// Propaga a excecao ORIGINAL lancada pelo metodo para o chamador poder
			// avaliar o requisito "nunca lanca excecao".
			throw ite.getTargetException();
		}
	}

	private SignaturePolicy loadRealPolicy(Policies policy) {
		PolicyFactory factory = PolicyFactory.getInstance();
		SignaturePolicy sp = factory.loadPolicy(policy);
		assertNotNull("politica nao carregada: " + policy.name(), sp);
		assertNotNull("signPolicyHash ausente na politica: " + policy.name(), sp.getSignPolicyHash());
		assertNotNull("signPolicyHashAlg ausente na politica: " + policy.name(), sp.getSignPolicyHashAlg());
		return sp;
	}

	// ---------------------------------------------------------------------
	// Test 1: OID de hash desconhecido/nao-mapeavel -> fallback para o .der,
	//         sem excecao.
	// ---------------------------------------------------------------------
	@Test
	public void test1_oidDesconhecido_retornaValorDoDer_semExcecao() throws Throwable {
		SignaturePolicy sp = loadRealPolicy(Policies.AD_RB_CADES_2_3);

		// Guarda o valor original do .der ANTES de adulterar o algoritmo.
		ASN1OctetString derOriginal = sp.getSignPolicyHash().getDerOctetString();
		byte[] esperadoDer = derOriginal.getOctets();

		// Adultera o OID de signPolicyHashAlg para um valor nao-mapeavel usando os
		// setters existentes: oidToDigestName(...) deve retornar null e acionar o
		// fallback (WARNING + valor do .der), sem lancar.
		ObjectIdentifier oid = sp.getSignPolicyHashAlg().getAlgorithm();
		oid.setValue(OID_DESCONHECIDO);

		ASN1OctetString resultado;
		try {
			resultado = invokeValidated(sp);
		} catch (Throwable t) {
			fail("getValidatedPolicyHashOctetString() NAO deve lancar excecao para OID desconhecido; "
					+ "esperado fallback para o valor do .der. Lancou: " + t);
			return;
		}

		assertNotNull("resultado nao deve ser nulo (fallback deve retornar o valor do .der)", resultado);
		assertArrayEquals(
				"para OID de hash desconhecido, o resultado deve ser exatamente o valor do .der (fallback)",
				esperadoDer, resultado.getOctets());
		logger.info("test1 OK: OID desconhecido caiu no fallback para o valor do .der");
	}

	// ---------------------------------------------------------------------
	// Test 2: signPolicyHash adulterado (divergencia forcada) -> fallback para
	//         o valor do .der (Der_Hash) e warning logado.
	// ---------------------------------------------------------------------
	@Test
	public void test2_hashAdulterado_retornaValorDoDer() throws Throwable {
		SignaturePolicy sp = loadRealPolicy(Policies.AD_RB_CADES_2_3);

		// Forca divergencia: injeta um signPolicyHash claramente diferente do
		// recalculado. O algoritmo (signPolicyHashAlg) continua valido (SHA-256),
		// entao o recalculo ACONTECE, mas nao vai bater com este valor adulterado
		// -> deve cair no fallback retornando exatamente o Der_Hash adulterado.
		byte[] adulterado = new byte[32];
		for (int i = 0; i < adulterado.length; i++) {
			adulterado[i] = (byte) (0xAB ^ i);
		}
		ASN1OctetString derAdulterado = new DEROctetString(adulterado);
		sp.setSignPolicyHash(new SignPolicyHash(derAdulterado));

		ASN1OctetString resultado;
		try {
			resultado = invokeValidated(sp);
		} catch (Throwable t) {
			fail("getValidatedPolicyHashOctetString() NAO deve lancar excecao quando o hash diverge; "
					+ "esperado fallback (Der_Hash) + warning. Lancou: " + t);
			return;
		}

		assertNotNull("resultado nao deve ser nulo (fallback deve retornar Der_Hash)", resultado);
		assertArrayEquals(
				"quando o recalculo diverge do .der, o resultado deve ser exatamente o Der_Hash (fallback)",
				adulterado, resultado.getOctets());
		logger.info("test2 OK: hash divergente caiu no fallback para o Der_Hash adulterado");
	}

	// ---------------------------------------------------------------------
	// Test 3: qualquer erro durante o recalculo -> nunca lanca excecao; o metodo
	//         retorna algo utilizavel (o valor do .der).
	// ---------------------------------------------------------------------
	@Test
	public void test3_erroDuranteRecalculo_nuncaLanca() throws Throwable {
		SignaturePolicy sp = loadRealPolicy(Policies.AD_RB_CADES_2_3);
		byte[] esperadoDer = sp.getSignPolicyHash().getDerOctetString().getOctets();

		// Cenario de erro: OID nulo em signPolicyHashAlg. Isso tende a provocar
		// NullPointerException/estado invalido no caminho de recalculo; o metodo
		// DEVE capturar (try/catch) e cair no fallback, jamais propagando excecao.
		sp.getSignPolicyHashAlg().getAlgorithm().setValue(null);

		ASN1OctetString resultado = null;
		boolean lancou = false;
		Throwable capturada = null;
		try {
			resultado = invokeValidated(sp);
		} catch (AssertionError ae) {
			// Pre-task-7: metodo ainda nao existe -> teste vermelho controlado.
			throw ae;
		} catch (Throwable t) {
			lancou = true;
			capturada = t;
		}

		if (lancou) {
			fail("getValidatedPolicyHashOctetString() NUNCA deve lancar excecao que quebre a assinatura; "
					+ "qualquer erro no recalculo deve virar fallback + warning. Lancou: " + capturada);
		}
		assertNotNull("mesmo em erro, o metodo deve retornar algo utilizavel (fallback do .der)", resultado);
		assertArrayEquals(
				"em erro no recalculo, o resultado deve ser o valor do .der (fallback)",
				esperadoDer, resultado.getOctets());
		logger.info("test3 OK: erro no recalculo tratado como fallback, sem excecao");
	}

	// ---------------------------------------------------------------------
	// Test 4: politica real intacta (AD_RB) -> recalculo bate; o resultado e o
	//         valor recalculado (variante B) que, nas politicas reais, coincide
	//         com o valor do .der.
	// ---------------------------------------------------------------------
	@Test
	public void test4_politicaReal_recalculoBate_igualAoDer() throws Throwable {
		SignaturePolicy sp = loadRealPolicy(Policies.AD_RB_CADES_2_3);

		// Sanity: politica real usa SHA-256 (mapeavel).
		String oid = sp.getSignPolicyHashAlg().getAlgorithm().getValue();
		if (!OID_SHA256.equals(oid)) {
			logger.info("test4: politica usa OID de hash {} (esperado SHA-256 {})", oid, OID_SHA256);
		}

		byte[] esperadoDer = sp.getSignPolicyHash().getDerOctetString().getOctets();

		ASN1OctetString resultado;
		try {
			resultado = invokeValidated(sp);
		} catch (AssertionError ae) {
			// Pre-task-7: metodo ainda nao existe -> teste vermelho controlado.
			throw ae;
		} catch (Throwable t) {
			fail("getValidatedPolicyHashOctetString() nao deve lancar para politica real valida. Lancou: " + t);
			return;
		}

		assertNotNull("resultado nao deve ser nulo para politica real", resultado);
		// Para as politicas ICP-Brasil reais, o recalculado (variante B) coincide
		// com o valor do .der; portanto o resultado deve ser igual ao Der_Hash.
		assertArrayEquals(
				"para politica real onde o recalculo bate, o resultado deve coincidir com o valor do .der",
				esperadoDer, resultado.getOctets());
		logger.info("test4 OK: politica real -> recalculo bate e coincide com o valor do .der");
	}
}
