package org.demoiselle.signer.importador.io;

import java.util.Objects;

/**
 * Resultado classificado de UMA tentativa de GET executada por um {@link Transporte}.
 *
 * <p>Imutável. Em caso de sucesso, {@link #sucesso()} é {@code true}, {@link #conteudo()}
 * contém os bytes baixados e {@link #motivo()} é {@code null}. Em caso de falha,
 * {@link #sucesso()} é {@code false}, {@link #conteudo()} é {@code null} e
 * {@link #motivo()} identifica a causa (timeout, status != 200, IO).</p>
 */
public record ResultadoTentativa(boolean sucesso, byte[] conteudo, MotivoFalha motivo) {

	/** Cria um resultado de sucesso com os bytes baixados. */
	public static ResultadoTentativa sucesso(byte[] conteudo) {
		return new ResultadoTentativa(true, Objects.requireNonNull(conteudo, "conteudo"), null);
	}

	/** Cria um resultado de falha com o motivo classificado. */
	public static ResultadoTentativa falha(MotivoFalha motivo) {
		return new ResultadoTentativa(false, null, Objects.requireNonNull(motivo, "motivo"));
	}
}
