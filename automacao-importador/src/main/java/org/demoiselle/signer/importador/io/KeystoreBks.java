package org.demoiselle.signer.importador.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.nucleo.ParserCertificado;

/**
 * Manipula o keystore BKS de destino (Keystore_Final) nativamente via API do
 * BouncyCastle ({@code KeyStore.getInstance("BKS", "BC")}), sem recorrer a
 * subprocessos externos ({@code keytool}/{@code openssl}).
 *
 * <p>O caminho do keystore e a senha usados em todas as operacoes vem das opcoes
 * de CLI {@code --keystore} e {@code --senha} (com defaults sensatos), e nunca de
 * um caminho fixo no codigo, reforcando a execucao independente do layout do
 * repositorio.</p>
 *
 * <p>Responsabilidades desta classe:</p>
 * <ul>
 *   <li>{@code snapshot} — carrega o estado atual do keystore como
 *       {@link Certificado}s (lista vazia se o arquivo ainda nao existe).</li>
 *   <li>{@code gravarAtomico} — escrita atomica com backup e rollback.</li>
 * </ul>
 *
 * <p>Requirements: 1.7, 8.1, 8.2, 8.5, 10.2, 10.8.</p>
 */
public final class KeystoreBks {

	private static final String TIPO_BKS = "BKS";
	private static final String PROVIDER_BC = "BC";

	static {
		// Garante o provider BC disponivel para "BC" estar acessivel,
		// mesmo que o Main ainda nao o tenha registrado (idempotente).
		if (Security.getProvider(PROVIDER_BC) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Captura um snapshot dos certificados presentes no keystore BKS no caminho
	 * informado.
	 *
	 * <p>Se o arquivo nao existir, retorna uma lista vazia (primeira publicacao —
	 * Req 10.2). Caso contrario, carrega o keystore com
	 * {@code KeyStore.getInstance("BKS", "BC")} + {@code load(...)}, enumera os
	 * aliases e converte cada entrada de certificado X.509 em {@link Certificado}
	 * via {@link ParserCertificado#paraCertificado(X509Certificate)}. Aliases cujo
	 * certificado nao seja X.509 sao ignorados.</p>
	 *
	 * @param path  caminho do keystore BKS de destino (nao nulo; vindo de
	 *              {@code --keystore})
	 * @param senha senha do keystore (nao nula; vinda de {@code --senha})
	 * @return a lista de certificados presentes no keystore, ou lista vazia se o
	 *         arquivo nao existir
	 * @throws KeystoreException se o keystore existir mas nao puder ser carregado
	 *                           ou enumerado
	 */
	public List<Certificado> snapshot(Path path, char[] senha) {
		Objects.requireNonNull(path, "path");
		Objects.requireNonNull(senha, "senha");

		if (!Files.exists(path)) {
			return new ArrayList<>();
		}

		try {
			KeyStore keyStore = KeyStore.getInstance(TIPO_BKS, PROVIDER_BC);
			try (InputStream in = Files.newInputStream(path)) {
				keyStore.load(in, senha);
			}

			List<Certificado> certificados = new ArrayList<>();
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Certificate certificate = keyStore.getCertificate(alias);
				if (certificate instanceof X509Certificate x509) {
					certificados.add(ParserCertificado.paraCertificado(x509));
				}
			}
			return certificados;
		} catch (KeyStoreException | IOException | NoSuchProviderException
				| NoSuchAlgorithmException | CertificateException e) {
			throw new KeystoreException(
					"Falha ao capturar snapshot do keystore BKS em '" + path + "'", e);
		}
	}

	/**
	 * Grava os certificados informados no keystore BKS de destino de forma
	 * <b>atomica</b>, com <b>backup</b> do arquivo atual e <b>rollback</b> em caso
	 * de falha.
	 *
	 * <p>O record {@link Certificado} do dominio carrega apenas metadados
	 * normalizados e nao o material X.509 real necessario para
	 * {@code setCertificateEntry}. Por isso esta API recebe {@link EntradaKeystore},
	 * que associa o {@code aliasFinal} (ja unico case-insensitive, produzido pelo
	 * {@code GeradorAlias}) ao {@link X509Certificate} lido da staging. O
	 * {@code ComandoPersistir} (Task 15.2) faz o de-para entre
	 * {@link org.demoiselle.signer.importador.dominio.AtribuicaoAlias} e os
	 * {@link X509Certificate} correspondentes.</p>
	 *
	 * <p>Algoritmo:</p>
	 * <ol>
	 *   <li>Cria um {@code KeyStore.getInstance("BKS", "BC")} em memoria e o
	 *       inicializa com {@code load(null, senha)}.</li>
	 *   <li>Para cada entrada, chama {@code setCertificateEntry(aliasFinal, x509)}.
	 *       Os aliases ja vem unicos case-insensitive do {@code GeradorAlias};
	 *       nenhuma geracao de alias e refeita aqui.</li>
	 *   <li>Escreve o keystore com {@code store(...)} em um arquivo <b>temporario</b>
	 *       criado no <b>mesmo diretorio</b> de {@code path} (permite move atomico).</li>
	 *   <li>Se {@code path} ja existe, move o arquivo atual para um <b>backup</b>
	 *       ({@code path} + ".bak") antes de publicar o novo.</li>
	 *   <li>Publica com {@code Files.move(tmp, path, ATOMIC_MOVE)} (com fallback para
	 *       {@code REPLACE_EXISTING} quando o move atomico nao e suportado pelo
	 *       sistema de arquivos).</li>
	 *   <li>Em caso de sucesso, remove o backup.</li>
	 * </ol>
	 *
	 * <p>Em <b>qualquer</b> falha durante {@code store}/{@code move}, faz rollback:
	 * restaura o backup para {@code path} (se havia backup), remove o temporario e
	 * propaga uma {@link KeystoreException}.</p>
	 *
	 * @param entradas lista de (aliasFinal, X509Certificate) a gravar (nao nula)
	 * @param path     caminho do keystore BKS de destino (nao nulo; vindo de
	 *                 {@code --keystore})
	 * @param senha    senha do keystore (nao nula; vinda de {@code --senha})
	 * @throws KeystoreException se a gravacao falhar (o keystore original e
	 *                           restaurado antes da propagacao)
	 */
	public void gravarAtomico(List<EntradaKeystore> entradas, Path path, char[] senha) {
		Objects.requireNonNull(entradas, "entradas");
		Objects.requireNonNull(path, "path");
		Objects.requireNonNull(senha, "senha");

		Path absoluto = path.toAbsolutePath();
		Path diretorio = absoluto.getParent();

		Path temporario = null;
		Path backup = null;
		boolean backupCriado = false;

		try {
			// 1) Monta o keystore em memoria com todas as entradas.
			KeyStore keyStore = KeyStore.getInstance(TIPO_BKS, PROVIDER_BC);
			keyStore.load(null, senha);
			for (EntradaKeystore entrada : entradas) {
				keyStore.setCertificateEntry(entrada.aliasFinal(), entrada.certificado());
			}

			// 2) Escreve em arquivo temporario no mesmo diretorio (para move atomico).
			if (diretorio != null) {
				Files.createDirectories(diretorio);
			}
			temporario = Files.createTempFile(
					diretorio, absoluto.getFileName().toString() + ".", ".tmp");
			try (OutputStream out = Files.newOutputStream(temporario)) {
				keyStore.store(out, senha);
			}

			// 3) Faz backup do arquivo atual (se existir) antes de publicar.
			if (Files.exists(absoluto)) {
				backup = absoluto.resolveSibling(absoluto.getFileName().toString() + ".bak");
				Files.move(absoluto, backup, StandardCopyOption.REPLACE_EXISTING);
				backupCriado = true;
			}

			// 4) Publica o novo keystore de forma atomica (fallback para REPLACE_EXISTING).
			publicarAtomico(temporario, absoluto);
			temporario = null; // consumido pelo move

			// 5) Sucesso: remove o backup.
			if (backupCriado && backup != null) {
				Files.deleteIfExists(backup);
			}
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException
				| NoSuchProviderException | CertificateException | RuntimeException e) {
			rollback(absoluto, backup, backupCriado, temporario);
			throw new KeystoreException(
					"Falha ao gravar o keystore BKS em '" + path + "' (rollback aplicado)", e);
		}
	}

	/**
	 * Publica o arquivo temporario em {@code destino} priorizando
	 * {@link StandardCopyOption#ATOMIC_MOVE}, com fallback para
	 * {@link StandardCopyOption#REPLACE_EXISTING} quando o move atomico nao e
	 * suportado pelo sistema de arquivos.
	 */
	private static void publicarAtomico(Path temporario, Path destino) throws IOException {
		try {
			Files.move(temporario, destino, StandardCopyOption.ATOMIC_MOVE);
		} catch (AtomicMoveNotSupportedException naoSuporta) {
			Files.move(temporario, destino, StandardCopyOption.REPLACE_EXISTING);
		}
	}

	/**
	 * Restaura o estado anterior do keystore: recoloca o backup em {@code path} (se
	 * havia) e remove o arquivo temporario, sem mascarar a excecao original (falhas
	 * de limpeza sao suprimidas).
	 */
	private static void rollback(Path path, Path backup, boolean backupCriado, Path temporario) {
		try {
			if (temporario != null) {
				Files.deleteIfExists(temporario);
			}
		} catch (IOException ignorado) {
			// Limpeza best-effort; nao mascara a falha original.
		}
		if (backupCriado && backup != null) {
			try {
				Files.move(backup, path, StandardCopyOption.REPLACE_EXISTING);
			} catch (IOException ignorado) {
				// Limpeza best-effort; nao mascara a falha original.
			}
		}
	}

	/**
	 * Associa um {@code aliasFinal} (ja unico case-insensitive) ao
	 * {@link X509Certificate} real a ser gravado no keystore. Serve de ponte entre
	 * o {@link org.demoiselle.signer.importador.dominio.AtribuicaoAlias} (metadados)
	 * e o material X.509 lido da staging.
	 *
	 * @param aliasFinal  alias sob o qual o certificado sera gravado (nao nulo)
	 * @param certificado certificado X.509 real (nao nulo)
	 */
	public record EntradaKeystore(String aliasFinal, X509Certificate certificado) {
		public EntradaKeystore {
			Objects.requireNonNull(aliasFinal, "aliasFinal");
			Objects.requireNonNull(certificado, "certificado");
		}
	}

	/**
	 * Excecao de runtime especifica do modulo, lancada quando uma operacao sobre o
	 * keystore BKS falha (carga, enumeracao, gravacao ou rollback).
	 */
	public static final class KeystoreException extends RuntimeException {

		private static final long serialVersionUID = 1L;

		public KeystoreException(String mensagem, Throwable causa) {
			super(mensagem, causa);
		}
	}
}
