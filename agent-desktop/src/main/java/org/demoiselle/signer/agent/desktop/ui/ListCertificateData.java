package org.demoiselle.signer.agent.desktop.ui;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.AbstractAction;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import javax.swing.KeyStroke;
import javax.swing.SwingConstants;

import org.demoiselle.signer.agent.desktop.command.cert.Certificate;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsResponse;

public class ListCertificateData extends JDialog {

	private class CertificateData {
		public JRadioButton sentBy;
		public JLabel provider;
		public String alias;

		public CertificateData(String sentBy, String provider, String alias) {
			this.sentBy = new JRadioButton("<html><span style='font-size:8px;'>" + sentBy + "</span></html>");
			this.provider = new JLabel("<html><span style='font-size:8px;'>" + provider + "</span></html>");
			this.alias = alias;
			this.sentBy.setBackground(new Color(0xffffff));
			this.provider.setBackground(new Color(0xffffff));

		}
	}

	private String alias;
	private String provider;
	private static final long serialVersionUID = 1L;
	List<CertificateData> certs;

	public static void main(String[] args) {
		(new ListCertificateData(null)).init();
	}

	public void init() {
		initUI();
		setVisible(true);
	}

	public ListCertificateData(ListCertsResponse certificates) {
		certs = new ArrayList<ListCertificateData.CertificateData>();
		for (Certificate c : certificates.getCertificates()) {
			certs.add(new CertificateData(c.getSubject(), c.getProvider(), c.getAlias()));
		}

	}

	private void initUI() {

		setTitle("Seleção de Certificado");
		setSize(700, 380);
		setLocationRelativeTo(null);

		// Window Always on TOP
		setAlwaysOnTop(true);

		setLayout(null);
		setResizable(false);
		final ListCertificateData me = this;

		JPanel pane = (JPanel) getContentPane();
		JLabel title = new JLabel("<html><span style='font-size:15px;'>Selecione um dos Certificados</span></html>");

		JLabel sentBy = new JLabel("<html><span style='font-size:10px; font-weight: bold;'>Emitido Para</span></html>");
		JLabel providers = new JLabel("<html><span style='font-size:10px; font-weight: bold;'>Provedor</span></html>");

		JButton btnValidate = new JButton("Selecionar");
		JButton btnCancel = new JButton("Cancelar");

		pane.setBackground(new Color(0xffffff));

		btnValidate.setFocusPainted(false);
		btnValidate.setContentAreaFilled(false);

		btnCancel.setFocusPainted(false);
		btnCancel.setContentAreaFilled(false);

		ButtonGroup bG = new ButtonGroup();

		int ypos = 70;
		for (int i = 0; i < certs.size(); i++) {
			bG.add(certs.get(i).sentBy);

			certs.get(i).sentBy.setBounds(15, ypos, 450, 30);
			certs.get(i).provider.setBounds(470, ypos, 230, 30);

			pane.add(certs.get(i).sentBy);
			pane.add(certs.get(i).provider);

			JSeparator js = new JSeparator(SwingConstants.HORIZONTAL);
			pane.add(js);
			js.setBounds(10, ypos - 5, 680, 4);

			ypos += 40;
		}

		JSeparator js = new JSeparator(SwingConstants.HORIZONTAL);
		pane.add(js);
		js.setBounds(10, ypos - 5, 680, 4);

		pane.add(sentBy);
		pane.add(providers);
		sentBy.setBounds(12, 40, 450, 25);
		providers.setBounds(470, 40, 230, 25);

		pane.add(title);

		pane.add(btnValidate);
		pane.add(btnCancel);

		title.setBounds(12, 10, 500, 25);

		btnCancel.setBounds(this.getWidth() - 225, this.getHeight() - 50, 100, 30);
		btnValidate.setBounds(this.getWidth() - 120, this.getHeight() - 50, 100, 30);

		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				me.dispose();

			}
		});

		btnValidate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for (int i = 0; i < certs.size(); i++) {
					if (certs.get(i).sentBy.isSelected()) {
						alias = certs.get(i).alias;
					}
				}
			}
		});

		getRootPane().setDefaultButton(btnValidate);

		final AbstractAction escapeAction = new AbstractAction() {
			private static final long serialVersionUID = 1L;

			public void actionPerformed(ActionEvent e) {
				dispose();
			}
		};

		getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
				"ESCAPE_KEY");
		getRootPane().getActionMap().put("ESCAPE_KEY", escapeAction);

		btnValidate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				me.dispose();
			}
		});

		this.setModal(true);

	}

	public String getAlias() {
		return alias;
	}

	public String getProvider() {
		return provider;
	}

}
