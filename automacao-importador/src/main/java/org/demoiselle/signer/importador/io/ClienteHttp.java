package org.demoiselle.signer.importador.io;

import java.time.Duration;
import java.util.Objects;

/**
 * Cliente HTTP com política de retry, construído sobre um {@link Transporte} injetável.
 *
 * <p>Para cada recurso, executa um laço de até {@link #MAX_TENTATIVAS} tentativas: se
 * alguma tentativa sucede, retorna imediatamente {@link ResultadoDownload#sucesso}
 * com os bytes e o número da tentativa que teve sucesso; se todas as tentativas falham,
 * retorna {@link ResultadoDownload#falha} com o motivo classificado da última tentativa
 * (timeout, status != 200 ou IO).</p>
 *
 * <p>A lógica de retry opera exclusivamente sobre o {@link Transporte}, o que permite
 * testá-la com um transporte mock, sem rede real. A implementação de produção do
 * transporte é {@link TransporteHttp}, que usa {@code java.net.http.HttpClient} com
 * {@code HttpRequest} configurado com timeout de {@link #TIMEOUT}.</p>
 *
 * <p>Requirements: 2.3, 7.6.</p>
 */
public final class ClienteHttp {

	/** Número máximo de tentativas por recurso. */
	public static final int MAX_TENTATIVAS = 3;

	/** Tempo limite de cada tentativa. */
	public static final Duration TIMEOUT = Duration.ofSeconds(30);

	private final Transporte transporte;

	/**
	 * Cria um cliente sobre o transporte informado.
	 *
	 * @param transporte o transporte que executa cada tentativa individual (não nulo)
	 */
	public ClienteHttp(Transporte transporte) {
		this.transporte = Objects.requireNonNull(transporte, "transporte");
	}

	/**
	 * Cria um cliente com o transporte de produção ({@link TransporteHttp}).
	 */
	public static ClienteHttp comTransportePadrao() {
		return new ClienteHttp(new TransporteHttp());
	}

	/**
	 * Baixa o recurso da URL informada, aplicando o laço de até {@link #MAX_TENTATIVAS}
	 * tentativas.
	 *
	 * @param url a URL do recurso a baixar
	 * @return o resultado classificado do download (nunca {@code null})
	 */
	public ResultadoDownload baixar(String url) {
		Objects.requireNonNull(url, "url");
		MotivoFalha ultimoMotivo = MotivoFalha.IO;
		for (int tentativa = 1; tentativa <= MAX_TENTATIVAS; tentativa++) {
			ResultadoTentativa resultado = transporte.tentar(url);
			if (resultado.sucesso()) {
				return ResultadoDownload.sucesso(resultado.conteudo(), tentativa);
			}
			ultimoMotivo = resultado.motivo();
		}
		return ResultadoDownload.falha(ultimoMotivo, MAX_TENTATIVAS);
	}
}
