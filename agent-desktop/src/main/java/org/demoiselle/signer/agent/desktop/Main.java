package org.demoiselle.signer.agent.desktop;

import javax.servlet.ServletException;

import org.demoiselle.signer.agent.desktop.web.WSServer;
import org.demoiselle.signer.agent.desktop.web.WSServerSSL;

public class Main {
	
	public static void main(String[] args) throws ServletException {
		WSServer.getInstance();
		WSServerSSL.getInstance();
		new TrayIcon();
	}
}
