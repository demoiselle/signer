package org.demoiselle.signer.importador.io;

/**
 * Sinaliza que a área de <em>staging</em> está vazia: o {@code manifest.json} não
 * existe, ou existe mas não contém nenhum certificado
 * ({@code manifest.certificados()} nulo ou vazio).
 *
 * <p>É lançada por {@link StagingReader#lerManifest()} para permitir que o chamador
 * (por exemplo, o {@code ComandoPersistir} — Task 15.2) aborte a execução com a
 * mensagem "rode baixar primeiro", sem modificar o Keystore_Final (Req 1.6).</p>
 */
public class StagingVaziaException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public StagingVaziaException(String message) {
		super(message);
	}
}
