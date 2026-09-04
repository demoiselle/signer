package org.demoiselle.signer.importador.io;

/**
 * Abstração injetável do transporte HTTP: executa UMA tentativa de GET para uma URL
 * e retorna um {@link ResultadoTentativa} classificado (sucesso com bytes, ou falha
 * com motivo).
 *
 * <p>A separação em interface permite que a lógica de retry de {@link ClienteHttp}
 * seja testada com um transporte mock, sem depender de rede real. A implementação
 * de produção é {@link TransporteHttp}.</p>
 */
@FunctionalInterface
public interface Transporte {

	/**
	 * Executa uma única tentativa de GET para a URL informada.
	 *
	 * @param url a URL do recurso a baixar
	 * @return o resultado classificado da tentativa (nunca {@code null})
	 */
	ResultadoTentativa tentar(String url);
}
