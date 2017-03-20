package org.demoiselle.signer.agent.desktop;

import java.awt.Font;
import java.io.IOException;
import java.io.InputStream;
import java.net.BindException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ResourceBundle;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletException;
import javax.swing.JLabel;
import javax.swing.JOptionPane;

import org.demoiselle.signer.agent.desktop.web.WSServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Main {

	private static final Logger logger = LoggerFactory.getLogger(Main.class);

	private static final SplashScreenThread splash = new SplashScreenThread();

	public static void main(String[] args) throws ServletException {

		splash.start();

		Main.logger.info("Iniciando o Demoiselle Desktop Agent.");
		String version = ResourceBundle.getBundle("agent-desktop").getString("version");
		String urlVersionChecker = ResourceBundle.getBundle("agent-desktop").getString("urlVersionChecker");
		Main.logger.info("Versão: " + version);
		Main.logger.info("URL Version Checker: " + urlVersionChecker);
		try {
			if (Main.hasNewVersion(urlVersionChecker, version)) {
				JLabel label = new JLabel(
						"<html>Há uma nova versão disponível do Demoiselle Desktop Agent Component.<br/>"
								+ "É importante atualizar o aplicativo. Acesse o site e baixe a nova versão.</html>");
				label.setFont(new Font("Arial", Font.PLAIN, 14));

				JOptionPane.showMessageDialog(null, label, "Demoiselle Desktop Agent Component",
						JOptionPane.WARNING_MESSAGE);
			}
		} catch (Throwable error) {
			JLabel label = new JLabel("Não foi possível verificar se a aplicação está atualizada.");
			label.setFont(new Font("Arial", Font.PLAIN, 14));

			JOptionPane.showMessageDialog(null, label, "Demoiselle Desktop Agent Component",
					JOptionPane.WARNING_MESSAGE);
			System.exit(1);
		}

		try {
			WSServer.getInstance();
		} catch (RuntimeException error) {
			Throwable cause = error.getCause();
			if (cause instanceof BindException) {
				JLabel label = new JLabel(
						"Verifique se há outra instância da aplicação em execução e tente novamente.");
				label.setFont(new Font("Arial", Font.PLAIN, 14));

				JOptionPane.showMessageDialog(null, label, "Demoiselle Desktop Agent Component",
						JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}
			System.exit(1);
		}

		new TrayIcon();

	}

	private static boolean hasNewVersion(String stringURL, String currentVersion) {
		System.setProperty("jsse.enableSNIExtension", "false");
		URL url;
		try {
			url = new URL(stringURL);
		} catch (MalformedURLException e) {
			return false;
		}
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
			}
		} };
		HostnameVerifier valid = new HostnameVerifier() {
			public boolean verify(String h, SSLSession s) {
				return true;
			}
		};
		HttpsURLConnection.setDefaultHostnameVerifier(valid);
		try {
			SSLContext sc = SSLContext.getInstance("TLSv1.2");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (Throwable error) {
			return false;
		}
		URLConnection connection;
		try {
			connection = url.openConnection();
			connection.setConnectTimeout(2000);
			connection.setReadTimeout(2000);
			connection.connect();
		} catch (IOException e) {
			return false;
		}
		HttpsURLConnection https = (HttpsURLConnection) connection;
		String content = null;
		try {
			Main.logger.info("Verificando a versão mais nova através do link");
			InputStream is = (InputStream) https.getContent();
			byte[] readContent = new byte[https.getContentLength()];
			is.read(readContent);
			content = new String(readContent);
			content = content.trim();
			Main.logger.info("Versão do link: " + content);
		} catch (IOException e) {
			return false;
		}
		boolean hasNewVersion = ((content != null) && (!content.equalsIgnoreCase(currentVersion)));
		if (hasNewVersion) {
			Main.logger.info("Sim. Existe uma versão mais nova.");
		} else {
			Main.logger.info("Não existe atualização a ser feita.");
		}
		return hasNewVersion;
	}

}