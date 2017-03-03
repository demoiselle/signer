package org.demoiselle.signer.agent.desktop;

import javax.servlet.ServletException;

import org.demoiselle.signer.agent.desktop.web.WSServer;

public class Main {

	public static void main(String[] args) throws ServletException {
		WSServer.getInstance();

		// Up HTTPS server (Deprecated)
		// WSServerSSL.getInstance();

		new TrayIcon();
	}
}
