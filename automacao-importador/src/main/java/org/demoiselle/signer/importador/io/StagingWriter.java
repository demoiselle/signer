package org.demoiselle.signer.importador.io;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Objects;
import java.util.stream.Stream;

import org.demoiselle.signer.importador.dominio.Manifest;
import org.demoiselle.signer.importador.dominio.Origem;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.paramnames.ParameterNamesModule;

/**
 * Escreve a área de <em>staging</em> em disco: o layout de diretórios, os
 * certificados em DER (arquivos {@code .cer}) e o {@code manifest.json}.
 *
 * <p><strong>Raiz configurável.</strong> A raiz da staging é recebida no construtor
 * (proveniente da opção de CLI {@code --staging}, cujo default sensato é definido pelo
 * chamador). Nenhum caminho fixo amarrado ao layout do repositório é assumido.</p>
 *
 * <p><strong>Layout produzido</strong> (raiz = {@code <staging_root>}):</p>
 * <pre>
 * &lt;staging_root&gt;/
 * ├── manifest.json      (Manifest: certificados[], falhas[], homEsperadas[])
 * ├── pro/
 * │   └── &lt;arquivo&gt;.cer  (certificado em DER)
 * └── hom/
 *     └── &lt;arquivo&gt;.cer
 * </pre>
 * Cada certificado é gravado em DER sob {@code pro/} ou {@code hom/} conforme a
 * {@link Origem}.
 *
 * <p><strong>Idempotência por origem.</strong> A escrita é idempotente por origem: uma
 * fonte baixada com sucesso pode ter seus certificados regravados chamando
 * {@link #limparOrigem(Origem)} seguido de {@link #gravar(Origem, String, byte[])}, o
 * que substitui integralmente os certificados anteriores <em>daquela</em> origem. As
 * origens que não são regravadas (por exemplo, fontes que falharam no download)
 * permanecem preservadas em disco, pois nada nelas é tocado (Req 2.5, 1.4).</p>
 *
 * <p><strong>Serialização do manifest.</strong> O {@code manifest.json} é serializado
 * via Jackson. Como {@link Manifest} e os demais modelos de domínio são
 * {@code record}s, o {@link ObjectMapper} é configurado com o
 * {@link ParameterNamesModule} (nomes de componentes do record, dependendo do
 * compilador com a flag {@code -parameters}) e o {@link JavaTimeModule} (para
 * {@link java.time.Instant} serializado como ISO-8601, e não como timestamp
 * numérico). Ambas as dependências foram adicionadas ao {@code pom.xml} do módulo
 * ({@code jackson-datatype-jsr310} e {@code jackson-module-parameter-names}).</p>
 *
 * <p><strong>Nenhuma operação toca o Keystore_Final</strong> (Req 1.2, 2.2): esta
 * classe opera exclusivamente sobre o diretório de staging.</p>
 *
 * <p>Requirements: 2.2, 2.5, 1.4.</p>
 */
public final class StagingWriter {

	/** Nome do arquivo de manifest na raiz da staging. */
	public static final String ARQUIVO_MANIFEST = "manifest.json";

	private final Path raiz;
	private final ObjectMapper mapper;

	/**
	 * Cria um escritor de staging para a raiz informada.
	 *
	 * @param raiz a raiz da staging (proveniente de {@code --staging}; não nula)
	 */
	public StagingWriter(Path raiz) {
		this.raiz = Objects.requireNonNull(raiz, "raiz");
		this.mapper = criarMapper();
	}

	/**
	 * Cria e configura o {@link ObjectMapper} usado para serializar o manifest.
	 *
	 * <p>Exposto como estático para reutilização pelo {@code StagingReader} (Task
	 * 11.2), garantindo simetria de (des)serialização dos records de domínio.</p>
	 *
	 * @return um {@link ObjectMapper} pronto para (des)serializar o {@link Manifest}
	 */
	public static ObjectMapper criarMapper() {
		return new ObjectMapper()
				.registerModule(new ParameterNamesModule())
				.registerModule(new JavaTimeModule())
				.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
				.enable(SerializationFeature.INDENT_OUTPUT);
	}

	/**
	 * Prepara o layout da staging: cria a raiz e os diretórios {@code pro/} e
	 * {@code hom/} caso ainda não existam.
	 *
	 * <p>É seguro chamar múltiplas vezes: diretórios já existentes são preservados
	 * (não há remoção de conteúdo), o que mantém intactas as fontes já gravadas.</p>
	 *
	 * @throws UncheckedIOException se algum diretório não puder ser criado
	 */
	public void preparar() {
		try {
			Files.createDirectories(raiz);
			for (Origem origem : Origem.values()) {
				Files.createDirectories(diretorioDe(origem));
			}
		} catch (IOException e) {
			throw new UncheckedIOException("Falha ao preparar a staging em " + raiz, e);
		}
	}

	/**
	 * Remove todos os certificados ({@code .cer}) previamente gravados para a origem
	 * informada, sem afetar outras origens nem o {@code manifest.json}.
	 *
	 * <p>Deve ser chamado antes de regravar uma origem baixada com sucesso, de modo
	 * que os novos certificados <em>substituam</em> os anteriores daquela origem. As
	 * demais origens permanecem preservadas (Req 2.5).</p>
	 *
	 * @param origem a origem cujo diretório será esvaziado
	 * @throws UncheckedIOException se a limpeza falhar
	 */
	public void limparOrigem(Origem origem) {
		Objects.requireNonNull(origem, "origem");
		Path dir = diretorioDe(origem);
		if (!Files.isDirectory(dir)) {
			return;
		}
		try (Stream<Path> arquivos = Files.list(dir)) {
			arquivos.filter(Files::isRegularFile)
					.filter(p -> p.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".cer"))
					.forEach(p -> {
						try {
							Files.delete(p);
						} catch (IOException e) {
							throw new UncheckedIOException("Falha ao remover " + p, e);
						}
					});
		} catch (IOException e) {
			throw new UncheckedIOException("Falha ao limpar a origem " + origem + " em " + dir, e);
		}
	}

	/**
	 * Grava um certificado em DER sob o diretório da origem informada.
	 *
	 * <p>O nome de arquivo é normalizado para garantir a extensão {@code .cer} e para
	 * não escapar do diretório da origem (o nome é reduzido ao seu último segmento de
	 * caminho). A gravação é idempotente por arquivo: regravar o mesmo nome
	 * sobrescreve o conteúdo anterior.</p>
	 *
	 * @param origem      a origem do certificado ({@code PRO} ou {@code HOM})
	 * @param nomeArquivo o nome-base do arquivo {@code .cer} a gravar
	 * @param der         os bytes do certificado em codificação DER
	 * @return o caminho relativo (a partir da raiz da staging) do arquivo gravado,
	 *         em notação com barras {@code /}, apto a ser referenciado no
	 *         {@code Certificado.arquivo}
	 * @throws UncheckedIOException se a gravação falhar
	 */
	public String gravar(Origem origem, String nomeArquivo, byte[] der) {
		Objects.requireNonNull(origem, "origem");
		Objects.requireNonNull(nomeArquivo, "nomeArquivo");
		Objects.requireNonNull(der, "der");

		String nomeSeguro = normalizarNome(nomeArquivo);
		Path destino = diretorioDe(origem).resolve(nomeSeguro);
		try {
			Files.createDirectories(destino.getParent());
			Files.write(destino, der);
		} catch (IOException e) {
			throw new UncheckedIOException("Falha ao gravar certificado " + destino, e);
		}
		return subpastaDe(origem) + "/" + nomeSeguro;
	}

	/**
	 * Serializa o {@link Manifest} informado em {@code <staging_root>/manifest.json},
	 * preservando integralmente as listas de {@code certificados}, {@code falhas} e
	 * {@code homEsperadas} (Req 1.4, 2.5). Sobrescreve um manifest anterior.
	 *
	 * @param manifest o manifest a serializar (não nulo)
	 * @throws UncheckedIOException se a serialização ou a escrita falhar
	 */
	public void escreverManifest(Manifest manifest) {
		Objects.requireNonNull(manifest, "manifest");
		Path arquivo = raiz.resolve(ARQUIVO_MANIFEST);
		try {
			Files.createDirectories(raiz);
			byte[] json = mapper.writeValueAsBytes(manifest);
			Files.write(arquivo, json);
		} catch (IOException e) {
			throw new UncheckedIOException("Falha ao escrever o manifest em " + arquivo, e);
		}
	}

	/** Raiz da staging usada por este escritor. */
	public Path raiz() {
		return raiz;
	}

	private Path diretorioDe(Origem origem) {
		return raiz.resolve(subpastaDe(origem));
	}

	private static String subpastaDe(Origem origem) {
		return switch (origem) {
			case PRO -> "pro";
			case HOM -> "hom";
		};
	}

	/**
	 * Reduz o nome a um único segmento (evitando travessia de diretório) e garante a
	 * extensão {@code .cer}.
	 */
	private static String normalizarNome(String nomeArquivo) {
		String base = Path.of(nomeArquivo).getFileName().toString();
		if (base.isBlank()) {
			throw new IllegalArgumentException("nomeArquivo invalido: '" + nomeArquivo + "'");
		}
		if (!base.toLowerCase(java.util.Locale.ROOT).endsWith(".cer")) {
			base = base + ".cer";
		}
		return base;
	}
}
