/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 * 
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 * 
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 * 
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 * 
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.jnlp.view;

import java.awt.Cursor;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.security.KeyStore;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.WindowConstants;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import org.demoiselle.signer.jnlp.action.FrameExecute;
import org.demoiselle.signer.jnlp.config.FrameConfig;
import org.demoiselle.signer.jnlp.factory.FrameExecuteFactory;
import org.demoiselle.signer.jnlp.handler.PinCallbackHandler;
import org.demoiselle.signer.jnlp.tiny.Item;
import org.demoiselle.signer.signature.core.exception.CertificateValidatorException;
import org.demoiselle.signer.signature.core.keystore.loader.DriverNotAvailableException;
import org.demoiselle.signer.signature.core.keystore.loader.InvalidPinException;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.signature.core.keystore.loader.PKCS11NotFoundException;
import org.demoiselle.signer.signature.core.keystore.loader.factory.KeyStoreLoaderFactory;

/**
 * To design a main view with digital signature commands Execute and Cancel
*/
public class MainFrame extends javax.swing.JFrame {

	private static final long serialVersionUID = 1L;
	
	private JButton btnCancel;
	private JButton btnExecute;
	private JPanel panelbottom;
	private JPanel paneltop;
	private JScrollPane scrollPane;
	private JScrollPane scrollPaneFiles;
	private JTable tableCertificates;
	private static JList<String> listFiles;
	
	
	KeyStore keystore = null;
	private static boolean loadedFiles = false;
	String alias = "";
	String className = "";
	CertificateModel certificateModel;

	/**
	 * Creates new form 
	 */
	public MainFrame() {
		initComponents();
		className = System.getProperty("jnlp.myClassName");

		if (className == null || className.isEmpty()) {
			className = "org.demoiselle.signer.jnlp.user.App";
		}
		FrameExecute frameExecute = FrameExecuteFactory.factory(className);

		while (keystore == null){
			keystore = this.getKeyStore();// Recupera o repositorio de certificados digitais
		}

		certificateModel = new CertificateModel();
		certificateModel.populate(keystore);
		tableCertificates.setModel(certificateModel);

		if (tableCertificates.getRowCount() == 0) {
			btnExecute.setEnabled(false);
		} else {
			tableCertificates.setRowSelectionInterval(0, 0);
		}

		tableCertificates.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

		// Dimensiona cada coluna separadamente
		TableColumn tableColumn1 = tableCertificates.getColumnModel().getColumn(0);
		tableColumn1.setPreferredWidth(200);

		TableColumn tableColumn2 = tableCertificates.getColumnModel().getColumn(1);
		tableColumn2.setPreferredWidth(140);

		TableColumn tableColumn3 = tableCertificates.getColumnModel().getColumn(2);
		tableColumn3.setPreferredWidth(140);

		TableColumn tableColumn4 = tableCertificates.getColumnModel().getColumn(3);
		tableColumn4.setPreferredWidth(300);

		this.setLocationRelativeTo(null); // Centraliza o frame

		this.addWindowListener(new WindowListener() {
			
			@Override
			public void windowIconified(WindowEvent e) {}
			@Override
			public void windowDeiconified(WindowEvent e) {}
			@Override
			public void windowDeactivated(WindowEvent e) {}
			
			@Override
			public void windowClosed(WindowEvent e) {}
			
			@Override
			public void windowActivated(WindowEvent e) {}

			@Override
			public void windowOpened(WindowEvent e) {}
			
			@Override
			public void windowClosing(WindowEvent e) {
				closeWindow(e);
			}

		});
		
		
	}

	private void initComponents() {

		paneltop = new JPanel();
		scrollPane = new JScrollPane();
		scrollPaneFiles = new JScrollPane();
		tableCertificates = new JTable();
		panelbottom = new JPanel();
		btnExecute = new JButton();
		btnCancel = new JButton();
		listFiles = new JList<String>();
				
		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		setLocation(new Point(0, 0));
		setResizable(false);
		setTitle(FrameConfig.LABEL_DIALOG_FRAME_TITLE.getValue());


		scrollPane.setAutoscrolls(true);
		scrollPane.setViewportView(tableCertificates);
		scrollPane.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createEtchedBorder(),
				FrameConfig.CONFIG_DIALOG_TABLE_LABEL.getValue(),
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION,
				new java.awt.Font(FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT.getValue(), FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT_STYLE.getValueInt(), FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT_SIZE.getValueInt()))); // NOI18N

		
		tableCertificates.setBorder(BorderFactory.createEmptyBorder(1, 1, 1, 1));
		tableCertificates.setModel(new DefaultTableModel(
				new Object[][] { { null, null, null, null },
						{ null, null, null, null }, { null, null, null, null },
						{ null, null, null, null } }, new String[] { "Title 1",
						"Title 2", "Title 3", "Title 4" }));
		tableCertificates.setFillsViewportHeight(true);
		tableCertificates.setRowHeight(FrameConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_ROW_HEIGHT.getValueInt());

		scrollPaneFiles.setAutoscrolls(true);
		scrollPaneFiles.setViewportView(listFiles);
		scrollPaneFiles.setBorder(BorderFactory.createTitledBorder(
				BorderFactory.createEtchedBorder(),
				FrameConfig.CONFIG_DIALOG_LIST_FILES_LABEL.getValue(),
				TitledBorder.DEFAULT_JUSTIFICATION,
				TitledBorder.DEFAULT_POSITION,
				new java.awt.Font(FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT.getValue(), FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT_STYLE.getValueInt(), FrameConfig.CONFIG_DIALOG_TABLE_LABEL_FONT_SIZE.getValueInt())));


		listFiles.setEnabled(false);
		System.out.println("Tamanho: "+listFiles.getModel().getSize());
		
		GroupLayout paneltopLayout = new GroupLayout(paneltop);
		paneltop.setLayout(paneltopLayout);
		
		paneltopLayout.setHorizontalGroup(paneltopLayout.createParallelGroup(Alignment.LEADING)
				.addComponent(scrollPane, GroupLayout.DEFAULT_SIZE,	FrameConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_WIDTH.getValueInt(), Short.MAX_VALUE)
				.addComponent(scrollPaneFiles, GroupLayout.DEFAULT_SIZE,	FrameConfig.CONFIG_DIALOG_LIST_FILES_WIDTH.getValueInt(), Short.MAX_VALUE));
		
		paneltopLayout.setVerticalGroup(paneltopLayout.createSequentialGroup()
				.addComponent(scrollPane,GroupLayout.PREFERRED_SIZE,FrameConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_HEIGHT.getValueInt(),GroupLayout.PREFERRED_SIZE)
				.addComponent(scrollPaneFiles,GroupLayout.PREFERRED_SIZE,FrameConfig.CONFIG_DIALOG_LIST_FILES_HEIGHT.getValueInt(),GroupLayout.PREFERRED_SIZE));
	
		panelbottom.setBorder(BorderFactory.createEtchedBorder());

		btnExecute.setText(FrameConfig.LABEL_DIALOG_BUTTON_RUN.getValue());
		btnExecute.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				btnExecuteActionPerformed(evt);
			}
		});

		btnCancel.setText(FrameConfig.LABEL_DIALOG_BUTTON_CANCEL.getValue());
		btnCancel.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent evt) {
				btnCancelActionPerformed(evt);
			}
		});
		
		GroupLayout panelbottomLayout = new GroupLayout(panelbottom);
		panelbottom.setLayout(panelbottomLayout);
		panelbottomLayout.setHorizontalGroup(panelbottomLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(panelbottomLayout.createSequentialGroup()
								.addComponent(btnExecute,GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_RUN_WIDTH.getValueInt(), GroupLayout.PREFERRED_SIZE)
								.addComponent(btnCancel, GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_CANCEL_WIDTH.getValueInt(), GroupLayout.PREFERRED_SIZE)
						));
		panelbottomLayout.setVerticalGroup(panelbottomLayout.createParallelGroup(Alignment.LEADING)
						.addGroup(panelbottomLayout.createSequentialGroup()
								.addContainerGap()
								.addGroup(panelbottomLayout.createParallelGroup(Alignment.BASELINE)
										.addComponent(btnExecute, GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_RUN_HEIGHT.getValueInt(), GroupLayout.PREFERRED_SIZE)
										.addComponent(btnCancel, GroupLayout.PREFERRED_SIZE, FrameConfig.CONFIG_DIALOG_BUTTON_CANCEL_HEIGHT.getValueInt(), GroupLayout.PREFERRED_SIZE)
								)
								.addContainerGap()
						));
	
		GroupLayout layout = new GroupLayout(getContentPane());
		getContentPane().setLayout(layout);
		layout.setHorizontalGroup(layout.createParallelGroup(Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
								.addContainerGap()
								.addGroup(layout.createParallelGroup(Alignment.LEADING,	false)
												.addComponent(paneltop, GroupLayout.DEFAULT_SIZE,GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
												.addComponent(panelbottom, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
								.addContainerGap(GroupLayout.DEFAULT_SIZE,Short.MAX_VALUE)));
		layout.setVerticalGroup(layout.createParallelGroup(Alignment.LEADING)
				.addGroup(layout.createSequentialGroup()
								.addContainerGap()
								.addComponent(paneltop, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addPreferredGap(ComponentPlacement.RELATED)
								.addComponent(panelbottom, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)));

		pack();
	}

	private void btnExecuteActionPerformed(java.awt.event.ActionEvent evt) {
		FrameExecute frameExecute = FrameExecuteFactory.factory(className);
		alias = this.getAlias();
		frameExecute.execute(keystore, alias, this);
	}

	private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {
		FrameExecute frameExecute = FrameExecuteFactory.factory(className);
		alias = this.getAlias();
		frameExecute.cancel(keystore, alias, this);
	}
	
	private void closeWindow(WindowEvent e) {
		FrameExecute frameExecute = FrameExecuteFactory.factory(className);
		alias = this.getAlias();
		frameExecute.close(this);
	}
	
	
	/**
	 * Retorna o keystore do dispositivo a partir do valor de pin
	 *
	 * @return
	 */
	public KeyStore getKeyStore() {
		try {
			Cursor hourGlassCursor = new Cursor(Cursor.WAIT_CURSOR);
			setCursor(hourGlassCursor);
			KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
			loader.setCallbackHandler(new PinCallbackHandler());
			keystore = loader.getKeyStore();
			return keystore;

		} catch (DriverNotAvailableException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_DRIVER_NOT_AVAILABLE.getValue());
		} catch (PKCS11NotFoundException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_PKCS11_NOT_FOUND.getValue());
		} catch (CertificateValidatorException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_LOAD_TOKEN.getValue());
		} catch (InvalidPinException e) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_INVALID_PIN.getValue());
		} catch (KeyStoreLoaderException ke) {
			showFailDialog(ke.getMessage());
		} catch (Exception ex) {
			showFailDialog(FrameConfig.MESSAGE_ERROR_UNEXPECTED.getValue());
		} finally {
			Cursor hourGlassCursor = new Cursor(Cursor.DEFAULT_CURSOR);
			setCursor(hourGlassCursor);
		}
		return null;
	}

	/**
	 * Obtem o apelido associado a um certificado
	 *
	 * @return O apelido associado ao certificado
	 */
	public String getAlias() {
		if (tableCertificates.getModel().getRowCount() != 0) {
			int row = tableCertificates.getSelectedRow();
			Item item = (Item) tableCertificates.getModel().getValueAt(row, 0);
			return item.getAlias();
		} else {
			return "";
		}
	}

	/**
	 * Exibe as mensagens de erro
	 *
	 * @param message
	 */
	private void showFailDialog(String message) {
		JOptionPane.showMessageDialog(this, message,
				FrameConfig.LABEL_DIALOG_OPTION_PANE_TITLE.getValue(),
				JOptionPane.ERROR_MESSAGE);
	}   

	
    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(MainFrame.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
     
        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new MainFrame().setVisible(true);
            }
        });
    }
	
    public static void setListFileName(List<String> list){
    	DefaultListModel<String> files= new DefaultListModel<String>();
		listFiles.setModel(files);
		for (String string : list) {
			files.addElement(string);
		}
		setLoadedFiles(true);
    }

	public static boolean isLoadedFiles() {
		return loadedFiles;
	}

	public static void setLoadedFiles(boolean loadedFiles) {
		MainFrame.loadedFiles = loadedFiles;
	}
}