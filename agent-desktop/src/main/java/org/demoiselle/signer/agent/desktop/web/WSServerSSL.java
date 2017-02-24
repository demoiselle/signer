package org.demoiselle.signer.agent.desktop.web;

import static io.undertow.Handlers.path;
import static io.undertow.Handlers.websocket;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.BindException;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

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

		KeyStore localKeyStore = KeyStore.getInstance("JKS");
		InputStream is = WSServerSSL.class.getResourceAsStream("/localhost.jks");
		localKeyStore.load(is, "changeit".toCharArray());
		sslContext = SSLContext.getInstance("TLS");
		String defaultAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(defaultAlgorithm);
		keyManagerFactory.init(localKeyStore, "changeit".toCharArray());
		KeyManager[] km = keyManagerFactory.getKeyManagers();
		System.out.println(km);
		TrustManager[] tm = null;
		SecureRandom sr = null;
		sslContext.init(km, tm , sr);

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
		} catch (RuntimeException error ) {
			Throwable cause = error.getCause();
			if (cause instanceof BindException) {
				try {
					this.initializeWSServer(WSServerSSL.DEFAULT_HOST_WS_SERVER, WSServerSSL.DEFAULT_PORT_SSL_WS_SERVER);
				} catch (Throwable error2){
				}
			}
		}
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