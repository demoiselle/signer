package org.demoiselle.signer.importador.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Expande bundles de certificados ICP-Brasil para {@link X509Certificate}, sem
 * recorrer a subprocessos externos ({@code openssl}/{@code keytool}).
 *
 * <p>Substitui integralmente o uso de {@code openssl}:</p>
 * <ul>
 *   <li>O ZIP de produção ({@code ACcompactadox.zip}) é expandido via
 *       {@link java.util.zip.ZipInputStream}; cada entrada {@code .crt}/{@code .cer}
 *       é parseada como {@link X509Certificate} através de
 *       {@link CertificateFactory#getInstance(String)} para {@code "X.509"}.</li>
 *   <li>Arquivos {@code .p7b} (PKCS#7 / CMS) são expandidos via
 *       {@link org.bouncycastle.cms.CMSSignedData}, convertendo cada
 *       {@link X509CertificateHolder} contido em {@link X509Certificate} através de
 *       {@link JcaX509CertificateConverter} com o provider BouncyCastle.</li>
 * </ul>
 *
 * <p>Não aplica nenhum filtro por validade: todos os certificados encontrados são
 * retornados. Falhas de parsing são propagadas como {@link ExpansaoException}
 * (runtime), identificando a origem.</p>
 *
 * <p>Requirements: 2.1.</p>
 */
public final class ExpansorCertificados {

	private static final String PROVIDER_BC = "BC";

	static {
		// Garante o provider BC disponível para o converter, mesmo que o Main
		// ainda não o tenha registrado (idempotente).
		if (java.security.Security.getProvider(PROVIDER_BC) == null) {
			java.security.Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Expande o conteúdo de um ZIP de produção, extraindo os certificados das
	 * entradas com extensão {@code .crt} ou {@code .cer}.
	 *
	 * <p>Entradas de diretório e entradas cuja extensão não seja de certificado são
	 * ignoradas. Cada entrada de certificado é parseada como DER ou PEM via
	 * {@code CertificateFactory("X.509")}.</p>
	 *
	 * @param zipBytes os bytes do arquivo ZIP (não nulo)
	 * @return a lista de certificados extraídos, na ordem de leitura do ZIP
	 * @throws ExpansaoException se o ZIP não puder ser lido ou uma entrada de
	 *                           certificado não puder ser parseada
	 */
	public List<X509Certificate> expandirZip(byte[] zipBytes) {
		Objects.requireNonNull(zipBytes, "zipBytes");
		List<X509Certificate> certificados = new ArrayList<>();
		try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
			ZipEntry entrada;
			while ((entrada = zis.getNextEntry()) != null) {
				if (entrada.isDirectory() || !ehCertificado(entrada.getName())) {
					zis.closeEntry();
					continue;
				}
				byte[] bytes = lerEntrada(zis);
				zis.closeEntry();
				certificados.add(parsearCertificado(bytes, entrada.getName()));
			}
		} catch (IOException e) {
			throw new ExpansaoException("Falha ao ler o ZIP de certificados", e);
		}
		return certificados;
	}

	/**
	 * Expande um arquivo {@code .p7b} (PKCS#7 / CMS), retornando todos os
	 * {@link X509Certificate} nele contidos.
	 *
	 * <p>Tenta primeiro interpretar os bytes como CMS/DER; se isso falhar, tenta
	 * decodificá-los como PEM antes de reprocessar como CMS.</p>
	 *
	 * @param p7bBytes os bytes do arquivo {@code .p7b} (DER ou PEM; não nulo)
	 * @return a lista de certificados contidos no PKCS#7
	 * @throws ExpansaoException se o conteúdo não puder ser interpretado como PKCS#7
	 */
	public List<X509Certificate> expandirP7b(byte[] p7bBytes) {
		Objects.requireNonNull(p7bBytes, "p7bBytes");
		CMSSignedData cms;
		try {
			cms = new CMSSignedData(p7bBytes);
		} catch (CMSException derFalhou) {
			// Tenta interpretar como PEM (base64 entre cabeçalhos) e reprocessar.
			byte[] der = decodificarPem(p7bBytes);
			if (der == null) {
				throw new ExpansaoException(
						"Conteúdo p7b inválido: não é PKCS#7 DER nem PEM", derFalhou);
			}
			try {
				cms = new CMSSignedData(der);
			} catch (CMSException pemFalhou) {
				throw new ExpansaoException("Conteúdo p7b inválido após decodificação PEM", pemFalhou);
			}
		}

		JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(PROVIDER_BC);
		List<X509Certificate> certificados = new ArrayList<>();
		try {
			for (X509CertificateHolder holder : cms.getCertificates().getMatches(null)) {
				certificados.add(converter.getCertificate(holder));
			}
		} catch (CertificateException e) {
			throw new ExpansaoException("Falha ao converter certificado do PKCS#7", e);
		}
		return certificados;
	}

	/**
	 * Parseia um único certificado a partir de bytes em DER ou PEM, usando
	 * {@code CertificateFactory("X.509")}.
	 *
	 * @param bytes  os bytes do certificado (não nulo)
	 * @param origem identificador da origem, usado apenas em mensagens de erro
	 * @return o {@link X509Certificate} parseado
	 * @throws ExpansaoException se os bytes não representarem um certificado X.509
	 */
	public X509Certificate parsearCertificado(byte[] bytes, String origem) {
		Objects.requireNonNull(bytes, "bytes");
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
		} catch (CertificateException e) {
			throw new ExpansaoException("Falha ao parsear certificado X.509 de '" + origem + "'", e);
		}
	}

	private static boolean ehCertificado(String nome) {
		String lower = nome.toLowerCase(Locale.ROOT);
		return lower.endsWith(".crt") || lower.endsWith(".cer");
	}

	private static byte[] lerEntrada(InputStream in) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[8192];
		int lidos;
		while ((lidos = in.read(buffer)) != -1) {
			baos.write(buffer, 0, lidos);
		}
		return baos.toByteArray();
	}

	/**
	 * Decodifica um bloco PEM ({@code -----BEGIN ...-----}) para os bytes DER
	 * correspondentes. Retorna {@code null} se o conteúdo não parece PEM.
	 */
	private static byte[] decodificarPem(byte[] bytes) {
		String texto = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
		int inicio = texto.indexOf("-----BEGIN");
		if (inicio < 0) {
			return null;
		}
		int fimCabecalho = texto.indexOf('\n', inicio);
		int fim = texto.indexOf("-----END", fimCabecalho < 0 ? inicio : fimCabecalho);
		if (fimCabecalho < 0 || fim < 0) {
			return null;
		}
		String base64 = texto.substring(fimCabecalho + 1, fim)
				.replaceAll("\\s", "");
		try {
			return java.util.Base64.getDecoder().decode(base64);
		} catch (IllegalArgumentException e) {
			return null;
		}
	}

	/**
	 * Exceção de runtime lançada quando um bundle de certificados não pode ser
	 * expandido (ZIP corrompido, PKCS#7 inválido ou certificado não parseável).
	 */
	public static final class ExpansaoException extends RuntimeException {

		private static final long serialVersionUID = 1L;

		public ExpansaoException(String mensagem, Throwable causa) {
			super(mensagem, causa);
		}
	}
}
