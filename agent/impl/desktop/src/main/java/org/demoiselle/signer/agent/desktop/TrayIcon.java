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
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.demoiselle.signer.agent.desktop.command.cert.ListCerts;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsRequest;
import org.demoiselle.signer.agent.desktop.command.cert.ListCertsResponse;
import org.demoiselle.signer.agent.desktop.command.policy.ListPolicies;
import org.demoiselle.signer.agent.desktop.command.policy.ListPoliciesRequest;
import org.demoiselle.signer.agent.desktop.command.policy.ListPoliciesResponse;
import org.demoiselle.signer.agent.desktop.command.signer.FileSigner;
import org.demoiselle.signer.agent.desktop.ui.JFileChooserPolicy;
import org.demoiselle.signer.agent.desktop.ui.ListCertificateData;
import org.demoiselle.signer.agent.desktop.ui.SignatureInfo;
import org.demoiselle.signer.agent.desktop.ui.pdf.SignerPDF;
import org.demoiselle.signer.agent.desktop.web.WSServer;
import org.demoiselle.signer.signature.core.keystore.loader.configuration.Configuration;

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
					boolean isEnterpriseLicence = false;
					
					String enterpriseLicence = System.getProperty("DESKTOP_LICENCE");
					if(enterpriseLicence != null)
						isEnterpriseLicence = true;
					
					final java.awt.TrayIcon trayIcon = new java.awt.TrayIcon(image, "Demoiselle Signer 2.0.0-BETA1", popup);
					trayIcon.setImageAutoSize(true);
					
					MenuItem removeTray = new MenuItem("Remove Tray Icon");
					removeTray.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							tray.remove(trayIcon);
						}
					});
					popup.add(removeTray);
					popup.addSeparator();
					
					MenuItem closeMenu = new MenuItem("Close");
					closeMenu.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							WSServer.getInstance().stop();
							System.exit(0);
						}
					});
					popup.add(closeMenu);
					popup.addSeparator();
					
					MenuItem docSigner = new MenuItem("Assinar");
					docSigner.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							try {
								signer();
							} catch (IOException e1) {
								e1.printStackTrace();
							}
						}
					});
					popup.add(docSigner);
					popup.addSeparator();
					
					MenuItem docValidate = new MenuItem("Validar Assinatura");
					docValidate.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							try {
								validate();
							} catch (CertificateException e1) {
								e1.printStackTrace();
							} catch (IOException e1) {
								e1.printStackTrace();
							}
						}
					});
					popup.add(docValidate);
					popup.addSeparator();
					
					if(isEnterpriseLicence){
					MenuItem menuPdfSigner = new MenuItem("Assinar PDF");
					menuPdfSigner.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							
								try {
									pdfSigner();
								} catch (Throwable e1) {
									e1.printStackTrace();
								}
							
						}
					});
					popup.add(menuPdfSigner);
					popup.addSeparator();
					}
					
					
					MenuItem newDriver = new MenuItem("Adicionar driver do token");
					newDriver.addActionListener(new ActionListener() {
						public void actionPerformed(ActionEvent e) {
							try {
								addDriver();
							} catch (IOException e1) {
								// TODO Auto-generated catch block
								e1.printStackTrace();
							}
						}
					});
					popup.add(newDriver);
				
					
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
	
	public void signer() throws IOException{
		
		String fileName = "";
		String alias;
		
		ListCertsRequest requestCert = new ListCertsRequest();

		ListCerts ls = new ListCerts();
		ListCertsResponse lr = ls.doCommand(requestCert);
		if(lr.getCertificates().size() > 1){
			ListCertificateData lcd = new ListCertificateData(lr);
			lcd.init();
			alias = lcd.getAlias();
		}else
			alias = lr.getCertificates().iterator().next().getAlias();

		ListPoliciesResponse rp = (new ListPolicies()).doCommand(new ListPoliciesRequest());
		
		JFileChooserPolicy fileChooser = new JFileChooserPolicy(rp.getPolicies());
		
		int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
          File selectedFile = fileChooser.getSelectedFile();
          fileName = selectedFile.getAbsolutePath();
          FileSigner fs = new FileSigner();
          String signatureFileName = fs.sign(alias, fileChooser.getPolicy(), fileName);
          JOptionPane.showMessageDialog(null, "Arquivo de assinatuara disponível em: "+signatureFileName, 
        		  "Sucesso", JOptionPane.INFORMATION_MESSAGE);       
        }
		
	}
	
	public void pdfSigner() throws Throwable{
		
		String fileName = "";
		String alias;
		
		ListCertsRequest requestCert = new ListCertsRequest();

		ListCerts ls = new ListCerts();
		ListCertsResponse lr = ls.doCommand(requestCert);
		if(lr.getCertificates().size() > 1){
			ListCertificateData lcd = new ListCertificateData(lr);
			lcd.init();
			alias = lcd.getAlias();
		}else
			alias = lr.getCertificates().iterator().next().getAlias();

		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setAcceptAllFileFilterUsed(false);
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Pdf", "pdf");
		fileChooser.addChoosableFileFilter(filter);
		
		int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
          File selectedFile = fileChooser.getSelectedFile();
          fileName = selectedFile.getAbsolutePath();
          byte[] signature = new FileSigner().makeSignature(alias, null, fileName);
          SignerPDF pdf = new SignerPDF();
          try{
        	  pdf.doSigner(fileName, fileName+".p7s.pdf", signature);
          
          JOptionPane.showMessageDialog(null, "Arquivo de assinatuara disponível em: "+fileName, 
        		  "Sucesso", JOptionPane.INFORMATION_MESSAGE);
          }catch (Exception e) {
        	  JOptionPane.showMessageDialog(null, "Falha ao assinar: "+e.getMessage(), 
            		  "Falha", JOptionPane.ERROR_MESSAGE);
		}
        }
		
	}
	
	
	public void validate() throws CertificateException, IOException{
		String fileName = "";
		String signatureFileName = "";
		
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setDialogTitle("Selecione o arquivo de conteúdo");
		
		int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
          File selectedFile = fileChooser.getSelectedFile();
          fileName = selectedFile.getAbsolutePath();
          fileChooser.setDialogTitle("Selecione o arquivo de assinatura");
          returnValue = fileChooser.showOpenDialog(null);
          
          if (returnValue == JFileChooser.APPROVE_OPTION) {
            selectedFile = fileChooser.getSelectedFile();
            signatureFileName = selectedFile.getAbsolutePath();
            new SignatureInfo(fileName, signatureFileName).init();
          }
        }
		
		
	}
	
	public static void main(String[] args) throws IOException, InterruptedException{
		System.out.println(System.getProperty("java.version"));
		new TrayIcon().signer();
	}
	
	public void addDriver() throws IOException{
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setAcceptAllFileFilterUsed(false);
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Drivers", "so", "dll", "so.1", "so.2");
		fileChooser.addChoosableFileFilter(filter);
		int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
          File selectedFile = fileChooser.getSelectedFile();
          FileWriter prop = new FileWriter(Configuration.getConfigFilePath(), true);
          prop.write("Custom "+selectedFile.getName()+":"+selectedFile.getAbsolutePath());
          prop.flush();
          prop.close();
          
        }
        
	}
	
}