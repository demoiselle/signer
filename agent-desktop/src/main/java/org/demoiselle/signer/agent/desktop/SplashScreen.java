package org.demoiselle.signer.agent.desktop;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsEnvironment;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JWindow;
import javax.swing.SwingConstants;

public class SplashScreen extends JWindow {

	private static final long serialVersionUID = 1L;
	private int duration;

	public SplashScreen(int d) {
		duration = d;

		setAlwaysOnTop(true);

		JPanel content = (JPanel) getContentPane();
		content.setLayout(null);
		content.setBackground(Color.white);

		int width = 400;
		int height = 250;

		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
		int totalScreens = ge.getScreenDevices().length;

		Dimension screen = Toolkit.getDefaultToolkit().getScreenSize();
		int x = ((screen.width / totalScreens) / 2) - (width / 2);
		int y = (screen.height / 2) - (height / 2);

		setBounds(x, y, width, height);

		BufferedImage img = null;
		try {
			InputStream path = this.getClass().getClassLoader().getResourceAsStream("META-INF/ui/logo-signer.png");
			img = ImageIO.read(path);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		ImageIcon icon = new ImageIcon(img);
		JLabel lblImg = new JLabel(icon);
		lblImg.setHorizontalAlignment(SwingConstants.CENTER);
		lblImg.setBounds(0, 0, 400, 170);
		content.add(lblImg);

		// Action
		JLabel lblTitle = new JLabel("Assinador Digital (Demoiselle Signer)");
		lblTitle.setHorizontalAlignment(SwingConstants.CENTER);
		lblTitle.setFont(new Font("Arial", Font.PLAIN, 15));
		lblTitle.setBounds(0, 170, 400, 30);
		content.add(lblTitle);

		JLabel lblIcon = new JLabel("Utilize o ícone do assinador na bandeja para acessar as funcionalidades");
		lblIcon.setHorizontalAlignment(SwingConstants.CENTER);
		lblIcon.setFont(new Font("Arial", Font.PLAIN, 10));
		lblIcon.setBounds(0, 200, 400, 30);
		content.add(lblIcon);

		Color oraRed = new Color(255, 255, 255);
		content.setBorder(BorderFactory.createLineBorder(oraRed, 10));

		setVisible(true);
		try {
			Thread.sleep(duration);
		} catch (Exception e) {
		}
		setVisible(false);
	}

	public static void main(String[] args) {
		new SplashScreen(5000);
	}

}
