package org.demoiselle.signer.importador.io;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Objects;

/**
 * Implementação real de {@link Transporte} usando {@code java.net.http.HttpClient}.
 *
 * <p>Cada tentativa emite um {@code HttpRequest} GET com
 * {@code timeout(Duration.ofSeconds(30))} ({@link ClienteHttp#TIMEOUT}) e classifica o
 * resultado: sucesso (status 200 com bytes), falha por status (status != 200), falha por
 * timeout ou falha de IO.</p>
 */
public final class TransporteHttp implements Transporte {

	private final HttpClient httpClient;
	private final Duration timeout;

	/** Cria o transporte com o timeout padrão de {@link ClienteHttp#TIMEOUT}. */
	public TransporteHttp() {
		this(HttpClient.newHttpClient(), ClienteHttp.TIMEOUT);
	}

	/**
	 * Cria o transporte com um {@link HttpClient} e timeout específicos.
	 *
	 * @param httpClient o cliente HTTP a usar (não nulo)
	 * @param timeout    o tempo limite de cada tentativa (não nulo)
	 */
	public TransporteHttp(HttpClient httpClient, Duration timeout) {
		this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
		this.timeout = Objects.requireNonNull(timeout, "timeout");
	}

	@Override
	public ResultadoTentativa tentar(String url) {
		try {
			HttpRequest request = HttpRequest.newBuilder()
					.uri(URI.create(url))
					.timeout(timeout)
					.GET()
					.build();
			HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
			if (response.statusCode() == 200) {
				return ResultadoTentativa.sucesso(response.body());
			}
			return ResultadoTentativa.falha(MotivoFalha.STATUS);
		} catch (HttpTimeoutException e) {
			return ResultadoTentativa.falha(MotivoFalha.TIMEOUT);
		} catch (IOException e) {
			return ResultadoTentativa.falha(MotivoFalha.IO);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			return ResultadoTentativa.falha(MotivoFalha.IO);
		}
	}
}
