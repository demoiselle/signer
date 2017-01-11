package org.demoiselle.signer.agent.desktop.ui;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

import javax.swing.AbstractAction;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.signature.cades.SignerException;
import org.demoiselle.signer.signature.cades.factory.PKCS7Factory;
import org.demoiselle.signer.signature.cades.pkcs7.PKCS7Signer;
import org.demoiselle.signer.signature.core.ca.manager.CAManager;
import org.demoiselle.signer.signature.core.extension.BasicCertificate;

public class SignatureInfo extends JDialog{

	private static final long serialVersionUID = 1L;
	private String contentFileName;
	private String signedFileName;
	
	public static void main(String[] args) throws CertificateException, IOException{
		new SignatureInfo("/home/87450496968/Banner.pdf.p7s", "/home/87450496968/Banner.pdf.p7s").init();
	}
	
	public void init() throws CertificateException, IOException{
		initUI();
		setVisible(true);
	}
	
	public SignatureInfo(String contentFileName, String signedFileName){
		this.contentFileName = contentFileName;
		this.signedFileName = signedFileName;
	}
	
	private void initUI() throws CertificateException, IOException {
	
		
        setTitle("Informações da Assinatura");
        setSize(600, 350);
        setLocationRelativeTo(null);
		
		setLayout(null);
		setResizable(false);
		final SignatureInfo me = this;
			
        
		JPanel pane = (JPanel) getContentPane();
		
		
		byte[] content = readContent(contentFileName); 
		byte[] signed = readContent(signedFileName);
		
	
		PKCS7Signer signer = PKCS7Factory.getInstance().factoryDefault();
		try{
			signer.check(content, signed);
		}catch (Exception e) {
			URL urlCheck = getClass().getResource("/invalid.png");
			ImageIcon iconCheck = new ImageIcon(urlCheck);
			JLabel check = new JLabel(iconCheck);
			JLabel status = new JLabel("<html><span style='font-size:18px;font-weight: bold; color:#ff0000'>"
					+ "Assinatura digital inválida</span></html>");
			JLabel info = new JLabel("<html><span style='font-size:12px;font-weight: bold; color:#000000'>"
					+e.getMessage()+"</span></html>");
			pane.add(status);
	        pane.add(check);
	        pane.add(info);
	        
	        status.setBounds(100, 10, 580, 35);
	        info.setBounds(100, 55, 580, 55);
	        check.setBounds(20, 10, 50, 55);
	        setSize(600, 150);
			this.setModal(true);
			return;
		}
		
	
		LinkedList<X509Certificate> values = this.getCertData(content, signed);
		
		URL urlCertIcon = getClass().getResource("/certificate.png");
		ImageIcon iconCert = new ImageIcon(urlCertIcon);
		JLabel lblCertIcon = new JLabel(iconCert);
		JLabel lblCertText = new JLabel(values.get(0).getSubjectDN().getName());
		int y_init = 115;
		int x_init = 0;
		
		Iterator<X509Certificate> iter = values.iterator();
		while(iter.hasNext()){
			BasicCertificate bc = new BasicCertificate(iter.next());
			lblCertIcon = new JLabel(iconCert);
			lblCertText = new JLabel(bc.getNome());//values.get(i).getSubjectDN().getName());
			lblCertIcon.setBounds(x_init + 20, y_init, 20, 20);
			lblCertText.setBounds(x_init +52, y_init, 480, 20);
			pane.add(lblCertIcon);
			pane.add(lblCertText);
			x_init += 10;
			y_init += 20;
		}
		

		JLabel title = new JLabel("<html><span style='font-size:15px; color:#23527c'>Certificados Da Assinatura</span></html>");
			
		JLabel end = new JLabel("<html><span style='font-size:10px; color:#23527c'>Expira em:  "+values.get(0).getNotAfter()+"</span></html>");

		
		URL urlCheck = getClass().getResource("/check.png");
		ImageIcon iconCheck = new ImageIcon(urlCheck);
		JLabel check = new JLabel(iconCheck);
		JLabel status = new JLabel("<html><span style='font-size:18px;font-weight: bold; color:#008000ff'>"
				+ "Assinatura digital válida em conformidade ao padrão ICP-Brasil (DOC-ICP-15)</span></html>");
		
        JButton btnCancel = new JButton("Fechar");
        
        pane.setBackground(new Color(0xffffff));
        
        
        btnCancel.setFocusPainted(false);
        btnCancel.setContentAreaFilled(false);
        
        pane.add(status);
        pane.add(check);        
        pane.add(end);
        pane.add(title);        
        pane.add(btnCancel);
        
        btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				me.dispose();		
			}
		});
        
        final AbstractAction escapeAction = new AbstractAction() {
            private static final long serialVersionUID = 1L;

			public void actionPerformed(ActionEvent e) {
				dispose();
			}
        };

        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "ESCAPE_KEY");
        getRootPane().getActionMap().put("ESCAPE_KEY", escapeAction);

        
        status.setBounds(100, 10, 480, 55);
        check.setBounds(20, 10, 50, 55);
        end.setBounds(12, y_init + 50, 350, 15);
        title.setBounds(12, 80, 300, 25);        
        btnCancel.setBounds(this.getWidth()- 120, 300, 100, 30);
        
        this.setModal(true);
        
    }
	
	
	public <T> LinkedList<X509Certificate> getCertData(byte[] content, byte[] signed) throws CertificateException, IOException {
			
		Security.addProvider(new BouncyCastleProvider());
		CMSSignedData cmsSignedData = null;
		try {
			if (content == null) {
				cmsSignedData = new CMSSignedData(signed);
			} else {
				cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(
						content), signed);
			}
		} catch (CMSException ex) {
			throw new SignerException(
					"Bytes inválidos localizados no pacote PKCS7.", ex);
		}



		@SuppressWarnings("unchecked")
		Store<T> certStore = cmsSignedData.getCertificates();
		SignerInformationStore signers = cmsSignedData.getSignerInfos();
		Iterator<?> it = signers.getSigners().iterator();

		while (it.hasNext()) {
			
			
				SignerInformation signer = (SignerInformation) it.next();
				
				@SuppressWarnings("unchecked")
				Collection<T> certCollection = certStore.getMatches(signer.getSID());

				Iterator<?> certIt = certCollection.iterator();
				
				X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
				
				X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
				
				LinkedList<X509Certificate> cas = (LinkedList<X509Certificate>)CAManager.getInstance().getCertificateChain(cert);
				

				return cas;
				
		}

		
		return null;
	}

	
	
	private byte[] readContent(String arquivo) {
		
		byte[] result = null;
		try {
			File file = new File(arquivo);
			FileInputStream is = new FileInputStream(file);
			result = new byte[(int) file.length()];
			is.read(result);
			is.close();
		} catch (IOException ex) {
			ex.printStackTrace();
			System.out.println();
		}
		return result;
	}
}
