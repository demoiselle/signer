package org.demoiselle.signer.chain.icp.brasil.provider.hom;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Verificador de presenca da cadeia v12 no repositorio HOM.
 * Uso: java -cp <jars> org.demoiselle.signer.chain.icp.brasil.provider.hom.VerificarCadeiasV12
 */
public class VerificarCadeiasV12 {

	static final String INDEX_URL = "https://repositoriohom.serpro.gov.br/cadeias/index.html";
	static final String BASE_URL = "https://repositoriohom.serpro.gov.br/cadeias/";
	static final int TIMEOUT_MS = 15000;

	// CAs da cadeia v12 que esperamos encontrar
	static final CAExpectativa[] V12_ESPERADAS = {
		new CAExpectativa("AC Raiz Brasileira v12",
			"CN=Autoridade Certificadora Raiz Brasileira v12,OU=Instituto Nacional de Tecnologia da Informacao - ITI,O=ICP-Brasil,C=BR",
			"16510958650902378891", "RAIZ"),
		new CAExpectativa("AC SERPRO v5 - HOM",
			"CN=Autoridade Certificadora SERPRO v5 - HOM,OU=Autoridade Certificadora Raiz Brasileira v12,O=ICP-Brasil,C=BR",
			"14043476084434365245", "INTERMEDIARIA"),
		new CAExpectativa("AC SERPRO Final v6 - HOM",
			"CN=Autoridade Certificadora do SERPRO Final v6 - HOM,OU=Servico Federal de Processamento de Dados - SERPRO,O=ICP-Brasil,C=BR",
			"17483248897899078377", "FINAL"),
	};

	// Subjects da cadeia v2 (antiga)
	static final String[] V2_SUBJECT_MARKS = {
		"CN=Autoridade Certificadora Raiz Hom do SERPRO",
		"CN=Autoridade Certificadora Raiz Hom do SERPRO v2",
		"CN=Autoridade Certificadora SERPRO v2 - HOM",
		"CN=Autoridade Certificadora do SERPRO Final v6 - Hom",
	};

	static class CAExpectativa {
		String nome, subject, serial, tipo;
		CAExpectativa(String nome, String subject, String serial, String tipo) {
			this.nome = nome; this.subject = subject; this.serial = serial; this.tipo = tipo;
		}
	}

	static class CAInfo {
		String subject, serial, issuer, sourceFile;
		boolean selfSigned;
		CAInfo(String s, String ser, String iss, boolean self, String src) {
			subject = s; serial = ser; issuer = iss; selfSigned = self; sourceFile = src;
		}
	}

	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		trustAllSSL();

		System.out.println("================================================================");
		System.out.println("  VERIFICADOR: PRESENCA DA CADEIA v12 NO REPOSITORIO HOM");
		System.out.println("  URL: " + INDEX_URL);
		System.out.println("  Data: " + new Date());
		System.out.println("================================================================");

		List<String> files = fetchP7BList();
		if (files.isEmpty()) {
			System.out.println("ERRO: Nao foi possivel obter a lista de arquivos.");
			System.out.println("Verifique VPN/acesso a rede SERPRO.");
			System.exit(1);
		}

		System.out.println("\nTotal de arquivos .p7b encontrados: " + files.size());
		for (int i = 0; i < files.size(); i++) {
			System.out.printf("  %2d. %s%n", i + 1, files.get(i));
		}

		List<CAInfo> allCAs = new ArrayList<>();
		System.out.println("\n\n================================================================");
		System.out.println("  CONTEUDO DE CADA ARQUIVO .P7B");
		System.out.println("================================================================");

		for (String file : files) {
			List<CAInfo> cas = downloadParseP7B(file);
			if (cas == null || cas.isEmpty()) {
				System.out.printf("\n  >>> %s <<< (vazio/falha ao parsear)%n", file);
				continue;
			}
			System.out.printf("\n  >>> %s (%d certificado(s)) <<< %n", file, cas.size());
			for (CAInfo ca : cas) {
				System.out.printf("  Subject: %s%s%n", ca.subject, ca.selfSigned ? " [RAIZ]" : "");
				System.out.printf("  Serial:  %s%n", ca.serial);
				System.out.printf("  Issuer:  %s%n", ca.issuer);
				System.out.println();
			}
			allCAs.addAll(cas);
		}

		System.out.println("\n\n================================================================");
		System.out.println("  VERIFICACAO: CADEIA v12");
		System.out.println("================================================================");

		int v12Count = 0;
		for (CAExpectativa exp : V12_ESPERADAS) {
			boolean found = false;
			for (CAInfo ca : allCAs) {
				if (ca.serial.equals(exp.serial)) {
					found = true;
					break;
				}
			}
			if (found) {
				v12Count++;
				System.out.printf("  [OK] %s (%s)%n", exp.nome, exp.tipo);
			} else {
				System.out.printf("  [FALTA] %s (%s)%n", exp.nome, exp.tipo);
				System.out.printf("         Subject: %s%n", exp.subject);
				System.out.printf("         Serial:  %s%n", exp.serial);
			}
		}

		System.out.println("\nArquivos .p7b com CAs da CADEIA v2 (antiga):");
		Set<String> seen = new HashSet<>();
		boolean hasV2 = false;
		for (CAInfo ca : allCAs) {
			for (String mark : V2_SUBJECT_MARKS) {
				if (ca.subject.contains(mark) && seen.add(ca.subject + ca.serial)) {
					hasV2 = true;
					System.out.printf("    %s (serial %s) em %s%n", ca.subject, ca.serial, ca.sourceFile);
					break;
				}
			}
		}
		if (!hasV2) System.out.println("    (nenhuma)");

		System.out.println("\n\n================================================================");
		System.out.println("  RESUMO FINAL");
		System.out.println("================================================================");
		if (v12Count == 3) {
			System.out.println("  CADEIA v12 COMPLETA presente no repositorio.");
		} else if (v12Count > 0) {
			System.out.printf("  CADEIA v12 PARCIAL (%d/3).%n", v12Count);
		} else {
			System.out.println("\n  >>>>>> CADEIA v12 COMPLETAMENTE AUSENTE <<<<<<");
			System.out.println();
			System.out.println("  O repositorio HOM soh possui a CADEIA v2 (antiga):");
			System.out.println("    AC Raiz Hom do SERPRO v2 (fake) -> AC SERPRO v2 - HOM -> AC SERPRO Final v6 - Hom");
			System.out.println();
			System.out.println("  Faltam as 3 CAs da CADEIA v12:");
			for (CAExpectativa exp : V12_ESPERADAS) {
				System.out.printf("    %s (serial %s)%n", exp.subject, exp.serial);
			}
		}

		System.out.println("\n================================================================");
	}

	static void trustAllSSL() throws Exception {
		TrustManager[] tm = new TrustManager[] { new X509TrustManager() {
			public void checkClientTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) {}
			public void checkServerTrusted(java.security.cert.X509Certificate[] x509Certificates, String s) {}
			public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
		} };
		SSLContext ctx = SSLContext.getInstance("TLS");
		ctx.init(null, tm, new SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
		HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
	}

	static List<String> fetchP7BList() throws Exception {
		String html = httpGet(INDEX_URL);
		if (html == null || html.isEmpty()) return Collections.emptyList();

		Pattern p = Pattern.compile("href=\"([^\"]+\\.p7b)\"");
		Matcher m = p.matcher(html);
		Set<String> seen = new LinkedHashSet<>();
		while (m.find()) {
			String url = m.group(1);
			String fn = url.substring(url.lastIndexOf('/') + 1);
			seen.add(fn);
		}
		return new ArrayList<>(seen);
	}

	static List<CAInfo> downloadParseP7B(String filename) throws Exception {
		byte[] data = httpGetBytes(BASE_URL + filename);
		if (data == null || data.length == 0) return null;

		List<X509Certificate> certs;
		try {
			certs = parsePKCS7(data);
		} catch (Exception e) {
			try {
				// tenta como PEM
				String pem = new String(data, "ISO-8859-1");
				CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
				Collection<X509Certificate> col = (Collection<X509Certificate>) cf.generateCertificates(new ByteArrayInputStream(pem.getBytes("ISO-8859-1")));
				certs = new ArrayList<>(col);
			} catch (Exception e2) {
				return null;
			}
		}

		List<CAInfo> result = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		for (X509Certificate cert : certs) {
			String key = cert.getSubjectX500Principal().getName() + cert.getSerialNumber();
			if (seen.contains(key)) continue;
			seen.add(key);
			result.add(new CAInfo(
				cert.getSubjectX500Principal().getName(),
				cert.getSerialNumber().toString(),
				cert.getIssuerX500Principal().getName(),
				cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()),
				filename
			));
		}
		return result;
	}

	static List<X509Certificate> parsePKCS7(byte[] data) throws Exception {
		CMSSignedData cms = new CMSSignedData(data);
		List<X509Certificate> certs = new ArrayList<>();
		for (Object obj : cms.getCertificates().getMatches(null)) {
			X509CertificateHolder holder = (X509CertificateHolder) obj;
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(holder.getEncoded()));
			certs.add(cert);
		}
		return certs;
	}

	static String httpGet(String urlStr) throws Exception {
		byte[] data = httpGetBytes(urlStr);
		return data != null ? new String(data, "UTF-8") : null;
	}

	static byte[] httpGetBytes(String urlStr) throws Exception {
		URL url = new URL(urlStr);
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setConnectTimeout(TIMEOUT_MS);
		conn.setReadTimeout(TIMEOUT_MS);
		conn.setRequestMethod("GET");
		conn.setHostnameVerifier((hostname, session) -> true);
		int code = conn.getResponseCode();
		if (code != 200) return null;
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[4096];
		int n;
		try (InputStream in = conn.getInputStream()) {
			while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
		}
		return baos.toByteArray();
	}
}
