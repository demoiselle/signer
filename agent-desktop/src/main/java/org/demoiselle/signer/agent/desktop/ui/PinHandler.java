package org.demoiselle.signer.agent.desktop.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;

import javax.imageio.ImageIO;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;

public class PinHandler extends JDialog implements CallbackHandler {

	private static final long serialVersionUID = 1L;
	private char[] pwd = new char[] {};
	private String action;
	private boolean actionCanceled = false;

	public static void main(String[] args) {
		(new PinHandler("Component Test")).init();
	}

	public void init() {
		initUI();
		setVisible(true);
	}

	public PinHandler(String action) {
		this.action = action;
		this.setAlwaysOnTop(true);
	}

	private void initUI() {

		setTitle("Informe Sua Senha Para [" + action + "]");
		setSize(500, 320);
		setLocationRelativeTo(null);

		setLayout(null);
		setResizable(false);
		final PinHandler me = this;

		JPanel pane = (JPanel) getContentPane();
		final JPasswordField text = new JPasswordField();
		JLabel lblPin = new JLabel("Informe o Pin:");
		lblPin.setFont(new Font("Arial", Font.PLAIN, 12));

		// Action
		JLabel lblAction = new JLabel("O programa deseja efetuar a seguinte ação com seu certificado: ");
		lblAction.setHorizontalAlignment(SwingConstants.CENTER);
		lblAction.setFont(new Font("Arial", Font.PLAIN, 12));

		// Action
		JLabel lblActionUser = new JLabel(action);
		lblActionUser.setHorizontalAlignment(SwingConstants.CENTER);
		lblActionUser.setFont(new Font("Arial", Font.BOLD, 16));

		JButton btnValidate = new JButton("Validar");
		btnValidate.setFont(new Font("Arial", Font.PLAIN, 13));

		JButton btnCancel = new JButton("Cancelar");
		btnCancel.setFont(new Font("Arial", Font.PLAIN, 13));

		pane.setBackground(new Color(0xffffff));

		BufferedImage img = null;
		try {
			InputStream path = this.getClass().getClassLoader().getResourceAsStream("META-INF/ui/logo_serpro.png");
			img = ImageIO.read(path);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		ImageIcon icon = new ImageIcon(img);
		JLabel lblImg = new JLabel(icon);
		lblImg.setHorizontalAlignment(SwingConstants.CENTER);

		btnValidate.setFocusPainted(false);
		btnValidate.setContentAreaFilled(false);

		btnCancel.setFocusPainted(false);
		btnCancel.setContentAreaFilled(false);

		pane.add(lblImg);
		pane.add(btnValidate);
		pane.add(btnCancel);

		// Action
		pane.add(lblAction);
		pane.add(lblActionUser);

		pane.add(lblPin);
		pane.add(text);

		lblImg.setBounds(0, 20, 500, 120);

		lblAction.setBounds(0, 150, 500, 15);
		lblActionUser.setBounds(0, 180, 500, 20);

		lblPin.setBounds(20, 230, 100, 15);
		text.setBounds(120, 230, getWidth() - (50 + lblPin.getWidth()), 20);
		btnCancel.setBounds((int) (text.getBounds().getMaxX() - 210), 270, 100, 30);
		btnValidate.setBounds((int) (text.getBounds().getMaxX() - 100), 270, 100, 30);

		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				actionCanceled = true;
				me.dispose();
			}
		});

		getRootPane().setDefaultButton(btnValidate);

		final AbstractAction escapeAction = new AbstractAction() {
			private static final long serialVersionUID = 1L;

			public void actionPerformed(ActionEvent e) {
				actionCanceled = false;
				dispose();
			}
		};

		getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				"ESCAPE_KEY");
		getRootPane().getActionMap().put("ESCAPE_KEY", escapeAction);

		btnValidate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				pwd = text.getPassword();
				me.dispose();
			}
		});

		this.setModal(true);

	}

	public char[] getPwd() {
		return pwd;
	}

	public boolean getActionCanceled() {
		return actionCanceled;
	}

	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
		for (Callback callback : callbacks) {
			if (callback instanceof PasswordCallback) {
				initUI();
				setVisible(true);

				((PasswordCallback) callback).setPassword(pwd);
			} else {
				throw new UnsupportedCallbackException(callback,
						"Callback not supported " + callback.getClass().getName());
			}
		}
	}

}
