package org.demoiselle.signer.importador.io;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.Manifest;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Lê a área de <em>staging</em> gravada por {@link StagingWriter}: o
 * {@code <staging_root>/manifest.json} e os certificados (DER) por ele
 * referenciados.
 *
 * <p><strong>Raiz configurável.</strong> A raiz da staging é recebida no construtor
 * (proveniente da opção de CLI {@code --staging}, cujo default sensato é definido
 * pelo chamador). Nenhum caminho fixo amarrado ao layout do repositório é assumido.</p>
 *
 * <p><strong>Simetria de (des)serialização.</strong> O {@code manifest.json} é lido
 * com o mesmo {@link ObjectMapper} usado pelo {@link StagingWriter} — obtido via
 * {@link StagingWriter#criarMapper()} — garantindo que os {@code record}s de domínio
 * (com {@link java.time.Instant} em ISO-8601 e nomes de componentes preservados)
 * sejam desserializados exatamente como foram gravados.</p>
 *
 * <p><strong>Staging vazia (Req 1.5, 1.6).</strong> A staging é considerada vazia
 * quando o {@code manifest.json} não existe, ou existe mas
 * {@code manifest.certificados()} é nulo ou vazio. Nesse caso:</p>
 * <ul>
 *   <li>{@link #stagingVazia()} retorna {@code true};</li>
 *   <li>{@link #lerManifestSeExistir()} retorna {@link Optional#empty()};</li>
 *   <li>{@link #lerManifest()} lança {@link StagingVaziaException} — a forma
 *       recomendada para o {@code ComandoPersistir} (Task 15.2) abortar com a
 *       mensagem "rode baixar primeiro".</li>
 * </ul>
 *
 * <p><strong>Nenhuma operação toca o Keystore_Final</strong>: esta classe opera
 * exclusivamente sobre o diretório de staging.</p>
 *
 * <p>Requirements: 1.5, 1.6.</p>
 */
public final class StagingReader {

	private final Path raiz;
	private final ObjectMapper mapper;

	/**
	 * Cria um leitor de staging para a raiz informada.
	 *
	 * @param raiz a raiz da staging (proveniente de {@code --staging}; não nula)
	 */
	public StagingReader(Path raiz) {
		this.raiz = Objects.requireNonNull(raiz, "raiz");
		this.mapper = StagingWriter.criarMapper();
	}

	/**
	 * Indica se a staging está vazia: manifest inexistente, ou presente mas sem
	 * certificados (lista nula ou vazia).
	 *
	 * @return {@code true} se a staging está vazia; {@code false} caso contrário
	 * @throws UncheckedIOException se o manifest existir mas não puder ser lido
	 */
	public boolean stagingVazia() {
		return lerManifestSeExistir().isEmpty();
	}

	/**
	 * Lê o manifest se a staging não estiver vazia.
	 *
	 * @return {@link Optional} com o {@link Manifest} quando o manifest existe e
	 *         possui ao menos um certificado; {@link Optional#empty()} quando a
	 *         staging está vazia (manifest inexistente ou sem certificados)
	 * @throws UncheckedIOException se o manifest existir mas não puder ser lido ou
	 *         desserializado
	 */
	public Optional<Manifest> lerManifestSeExistir() {
		Path arquivo = raiz.resolve(StagingWriter.ARQUIVO_MANIFEST);
		if (!Files.isRegularFile(arquivo)) {
			return Optional.empty();
		}
		Manifest manifest;
		try {
			manifest = mapper.readValue(Files.readAllBytes(arquivo), Manifest.class);
		} catch (IOException e) {
			throw new UncheckedIOException("Falha ao ler o manifest em " + arquivo, e);
		}
		if (manifest == null || manifest.certificados() == null || manifest.certificados().isEmpty()) {
			return Optional.empty();
		}
		return Optional.of(manifest);
	}

	/**
	 * Lê o manifest, exigindo staging não vazia.
	 *
	 * @return o {@link Manifest} com ao menos um certificado
	 * @throws StagingVaziaException se a staging estiver vazia (manifest inexistente
	 *         ou sem certificados) — sinaliza ao chamador que o Processo_Baixar
	 *         precisa ser executado primeiro (Req 1.6)
	 * @throws UncheckedIOException se o manifest existir mas não puder ser lido
	 */
	public Manifest lerManifest() {
		return lerManifestSeExistir()
				.orElseThrow(() -> new StagingVaziaException(
						"Staging vazia em " + raiz + ": nenhum certificado encontrado. "
								+ "Execute o processo 'baixar' primeiro."));
	}

	/**
	 * Lê os bytes DER de um certificado referenciado no manifest.
	 *
	 * <p>O {@code caminhoRelativo} corresponde ao {@link Certificado#arquivo()}
	 * gravado pelo {@link StagingWriter} (notação com barras {@code /}, por exemplo
	 * {@code pro/AC-Raiz.cer}). O caminho é resolvido a partir da raiz da staging e
	 * validado para não escapar dela.</p>
	 *
	 * @param caminhoRelativo o caminho relativo do certificado (campo
	 *        {@code Certificado.arquivo})
	 * @return os bytes DER do certificado
	 * @throws IllegalArgumentException se o caminho escapar da raiz da staging
	 * @throws UncheckedIOException se o arquivo não puder ser lido
	 */
	public byte[] lerCertificadoDer(String caminhoRelativo) {
		Objects.requireNonNull(caminhoRelativo, "caminhoRelativo");
		Path destino = raiz.resolve(caminhoRelativo).normalize();
		if (!destino.startsWith(raiz.normalize())) {
			throw new IllegalArgumentException(
					"caminhoRelativo escapa da raiz da staging: '" + caminhoRelativo + "'");
		}
		try {
			return Files.readAllBytes(destino);
		} catch (IOException e) {
			throw new UncheckedIOException("Falha ao ler certificado " + destino, e);
		}
	}

	/**
	 * Lê os bytes DER de todos os certificados referenciados no manifest, na ordem em
	 * que aparecem em {@code manifest.certificados()}.
	 *
	 * @param manifest o manifest cujos certificados serão lidos (não nulo)
	 * @return a lista de bytes DER, na mesma ordem dos certificados no manifest
	 * @throws UncheckedIOException se algum arquivo não puder ser lido
	 */
	public List<byte[]> lerCertificadosDer(Manifest manifest) {
		Objects.requireNonNull(manifest, "manifest");
		List<Certificado> certs = manifest.certificados();
		if (certs == null) {
			return List.of();
		}
		return certs.stream()
				.map(Certificado::arquivo)
				.map(this::lerCertificadoDer)
				.toList();
	}

	/** Raiz da staging usada por este leitor. */
	public Path raiz() {
		return raiz;
	}
}
