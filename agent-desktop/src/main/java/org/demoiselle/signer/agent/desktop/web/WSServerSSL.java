package org.demoiselle.signer.agent.desktop.web;

import static io.undertow.Handlers.path;
import static io.undertow.Handlers.websocket;

import java.net.BindException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.demoiselle.signer.agent.desktop.ui.PinHandler;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;

import io.undertow.Undertow;
import io.undertow.websockets.WebSocketConnectionCallback;
import io.undertow.websockets.core.AbstractReceiveListener;
import io.undertow.websockets.core.BufferedTextMessage;
import io.undertow.websockets.core.WebSocketChannel;
import io.undertow.websockets.core.WebSockets;
import io.undertow.websockets.spi.WebSocketHttpExchange;

public class WSServerSSL extends AbstractReceiveListener {

	private static final String DEFAULT_HOST_WS_SERVER = "localhost";
	private static final int DEFAULT_PORT_SSL_WS_SERVER = 9443;
	private static WSServerSSL instance = null;

	private Undertow undertow = null;

	public static WSServerSSL getInstance() {
		if (WSServerSSL.instance == null)
			WSServerSSL.instance = new WSServerSSL();
		return WSServerSSL.instance;
	}

	private WSServerSSL() {
		try {
			this.initializeWSServer(WSServerSSL.DEFAULT_HOST_WS_SERVER, WSServerSSL.DEFAULT_PORT_SSL_WS_SERVER);
		} catch (Throwable error) {
			error.printStackTrace();
		}
		this.start();
	}

	private void initializeWSServer(String host, int port) throws Throwable {
		final WSServerSSL listener = this;

		System.setProperty("javax.net.debug", "all");
		SSLContext sslContext = SSLContext.getDefault();
		sslContext = SSLContext.getInstance("TLSv1.2");
		String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(defaultAlgorithm);
		// keyManagerFactory.init(this.getKeyStoreFromLocal(),
		// "changeit".toCharArray());
		keyManagerFactory.init(this.getKeyStoreFromToken(), null);
		KeyManager[] km = keyManagerFactory.getKeyManagers();
		System.out.println(km);
		TrustManager[] tm = new TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] c, String a) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] c, String a) throws CertificateException {
			}
		} };
		SecureRandom sr = new SecureRandom();
		sslContext.init(km, tm, sr);
		HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
			public boolean verify(String h, SSLSession s) {
				return true;
			}
		});

		this.undertow = Undertow.builder().addHttpsListener(port, host, sslContext)
				.setHandler(path().addPrefixPath("/", websocket(new WebSocketConnectionCallback() {
					public void onConnect(WebSocketHttpExchange exchange, WebSocketChannel channel) {
						channel.getReceiveSetter().set(listener);
						channel.resumeReceives();
					}
				}))).build();
	}

	public void start() {
		try {
			this.undertow.start();
		} catch (RuntimeException error) {
			Throwable cause = error.getCause();
			if (cause instanceof BindException) {
				try {
					this.initializeWSServer(WSServerSSL.DEFAULT_HOST_WS_SERVER, WSServerSSL.DEFAULT_PORT_SSL_WS_SERVER);
				} catch (Throwable error2) {
				}
			}
		}
	}

	// private KeyStore getKeyStoreFromLocal() {
	// try {
	// KeyStore localKeyStore = KeyStore.getInstance("JKS");
	// InputStream is = WSServerSSL.class.getResourceAsStream("/localhost.jks");
	// localKeyStore.load(is, "changeit".toCharArray());
	// return localKeyStore;
	// } catch (Throwable error) {
	// return null;
	// }
	// }

	private KeyStore getKeyStoreFromToken() {
		KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
		loader.setCallbackHandler(new PinHandler("Utilizar seu certificado para criar um programa local com uma conexão segura"));
		return loader.getKeyStore();
	}

	public void stop() {
		this.undertow.stop();
	}

	protected void onFullTextMessage(WebSocketChannel channel, BufferedTextMessage message) {
		String result = null;
		try {
			result = new Execute().executeCommand(message.getData());
			WebSockets.sendText(result, channel, null);
		} catch (InterpreterException error) {
			WebSockets.sendText("{ \"error\": \"Erro ao tentar interpretar o JSON\"}", channel, null);
		} catch (Throwable error) {
			WebSockets.sendText("{ \"error\": \"" + error.getMessage() + "\"}", channel, null);
		}
	}

	public static void main(String[] args) {
		WSServerSSL.getInstance();
	}
}