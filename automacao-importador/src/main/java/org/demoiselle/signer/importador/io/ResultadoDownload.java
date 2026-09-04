package org.demoiselle.signer.importador.io;

import java.util.Objects;

/**
 * Resultado classificado do download de um recurso após o laço de tentativas de
 * {@link ClienteHttp}.
 *
 * <p>Imutável. Em caso de sucesso, {@link #sucesso()} é {@code true},
 * {@link #conteudo()} contém os bytes e {@link #motivo()} é {@code null}. Em caso de
 * falha, {@link #sucesso()} é {@code false}, {@link #conteudo()} é {@code null} e
 * {@link #motivo()} identifica a causa da última tentativa. {@link #tentativas()}
 * informa quantas tentativas foram realizadas (1..{@link ClienteHttp#MAX_TENTATIVAS}).</p>
 */
public record ResultadoDownload(boolean sucesso, byte[] conteudo, MotivoFalha motivo, int tentativas) {

	/** Cria um resultado de sucesso com os bytes baixados e o número de tentativas gastas. */
	public static ResultadoDownload sucesso(byte[] conteudo, int tentativas) {
		return new ResultadoDownload(true, Objects.requireNonNull(conteudo, "conteudo"), null, tentativas);
	}

	/** Cria um resultado de falha com o motivo da última tentativa e o número de tentativas gastas. */
	public static ResultadoDownload falha(MotivoFalha motivo, int tentativas) {
		return new ResultadoDownload(false, null, Objects.requireNonNull(motivo, "motivo"), tentativas);
	}
}
