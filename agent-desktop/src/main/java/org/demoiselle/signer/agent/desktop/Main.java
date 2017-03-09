package org.demoiselle.signer.agent.desktop;

import java.net.BindException;

import javax.servlet.ServletException;
import javax.swing.JOptionPane;

import org.demoiselle.signer.agent.desktop.web.WSServer;

public class Main {

	public static void main(String[] args) throws ServletException {
		try {
			WSServer.getInstance();
		} catch (RuntimeException error) {
			Throwable cause = error.getCause();
			if (cause instanceof BindException) {
				JOptionPane.showMessageDialog(null,
						"Verifique se há outra instância da aplicação em execução e tente novamente.",
						"Demoiselle Desktop Agent Component", JOptionPane.WARNING_MESSAGE);
				System.exit(0);
			}
			System.exit(1);
		}

		// Up HTTPS server (Deprecated)
		// WSServerSSL.getInstance();

		new TrayIcon();
	}
}
