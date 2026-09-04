package org.demoiselle.signer.importador.io;

/**
 * Classificação do motivo de falha de uma tentativa/ download de recurso.
 *
 * <ul>
 *   <li>{@link #TIMEOUT} — a tentativa excedeu o tempo limite (30s).</li>
 *   <li>{@link #STATUS} — a resposta HTTP retornou um status diferente de 200.</li>
 *   <li>{@link #IO} — erro de entrada/saída (rede indisponível, conexão recusada, etc.).</li>
 * </ul>
 */
public enum MotivoFalha {
	TIMEOUT,
	STATUS,
	IO
}
