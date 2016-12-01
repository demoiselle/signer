package org.demoiselle.signer.agent.desktop;

import java.awt.AWTException;
import java.awt.EventQueue;
import java.awt.Image;
import java.awt.MenuItem;
import java.awt.PopupMenu;
import java.awt.SystemTray;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;

import javax.swing.JOptionPane;

import org.demoiselle.signer.agent.desktop.web.WSServer;

public class TrayIcon {
	
	public TrayIcon() {
		this.makeTrayIcon();
	}

	public void makeTrayIcon() {
		Runnable runner = new Runnable() {
			public void run() {
				if (SystemTray.isSupported()) {
					final SystemTray tray = SystemTray.getSystemTray();
					URL urlImagem = getClass().getResource("/icone.jpeg");
					Image image = Toolkit.getDefaultToolkit().getImage(urlImagem);
					PopupMenu popup = new PopupMenu();
					final java.awt.TrayIcon trayIcon = new java.awt.TrayIcon(image, "Signer Agent Desktop", popup);
					trayIcon.setImageAutoSize(true);
					MenuItem removeTray = new MenuItem("Remove Tray Icon");
					removeTray.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							tray.remove(trayIcon);
						}
					});
					popup.add(removeTray);
					MenuItem closeMenu = new MenuItem("Close");
					closeMenu.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							WSServer.getInstance().stop();
							System.exit(0);
						}
					});
					popup.add(closeMenu);
					try {
						tray.add(trayIcon);
					} catch (AWTException e) {
					}
				} else {
					JOptionPane.showMessageDialog(null, "Sistema Operacional não suporta icones na bandeija!");
				}
			}
		};
		EventQueue.invokeLater(runner);
	}
	
}