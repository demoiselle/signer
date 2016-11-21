/*
 * Demoiselle Framework
 * Copyright (C) 2010 SERPRO
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
package org.demoiselle.signer.signature.applet.view;

import org.demoiselle.signer.signature.applet.config.AppletConfig;
import org.demoiselle.signer.signature.applet.handler.PinCallbackHandler;
import org.demoiselle.signer.signature.applet.tiny.Item;
import org.demoiselle.signer.signature.core.exception.CertificateValidatorException;
import org.demoiselle.signer.signature.core.keystore.loader.DriverNotAvailableException;
import org.demoiselle.signer.signature.core.keystore.loader.InvalidPinException;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.signature.core.keystore.loader.KeyStoreLoaderException;
import org.demoiselle.signer.signature.core.keystore.loader.PKCS11NotFoundException;
import org.demoiselle.signer.signature.core.keystore.loader.factory.KeyStoreLoaderFactory;

import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Rectangle;
import java.awt.event.ActionListener;
import java.awt.event.KeyListener;
import java.security.KeyStore;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.Border;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.TableColumn;

/**
 * JDialog especializado para obtencao do KeyStore de um dispositivo usb ou
 * smartcard.
 *
 * @author SUPST/STCTA
 *
 */
public class JKeyStoreDialog extends JDialog {

    private static final long serialVersionUID = 1L;

    private final JLabel certificatesLabel = new JLabel();
    private final JScrollPane scrollPane = new JScrollPane();
    private final JButton runButton = new JButton();
    private final JButton cancelButton = new JButton();
    private final JTable table = new JTable();
    private KeyStore keystore = null;
    private ListaCertificadosModel listaCertificadosModel = null;
    private boolean loaded = false;

    /**
     * Construtor. Aciona a inicializacao dos demais componentes
     */
    public JKeyStoreDialog() {
        init();
    }

    /**
     * Indica se o keystore foi carregado com sucesso.
     *
     * @return True, se for carregado com sucesso. False se contrario.
     */
    public boolean isLoaded() {
        return loaded;
    }

    /**
     * Inicializacao dos componentes
     */
    private void init() {
        mountGUI();
    }

    private void mountGUI() {

        try {
            this.setLayout(null);
            this.setSize(getDimension());

            // Label da tabela de certificados
            certificatesLabel.setText(AppletConfig.CONFIG_DIALOG_LABEL_TABLE.getValue());
            Border loweredetched = BorderFactory.createEtchedBorder(EtchedBorder.LOWERED);
            TitledBorder title = BorderFactory.createTitledBorder(loweredetched, certificatesLabel.getText());
            title.setTitleJustification(TitledBorder.CENTER);
            title.setTitleFont(new Font(AppletConfig.CONFIG_DIALOG_FONT.getValue(), AppletConfig.CONFIG_DIALOG_FONT_STYLE.getValueInt(), AppletConfig.CONFIG_DIALOG_FONT_SIZE.getValueInt()));

            // Configura a Tabela de Certificados
            listaCertificadosModel = new ListaCertificadosModel();
            listaCertificadosModel.populate(this.getKeyStore());
            table.setModel(listaCertificadosModel);

            if (table.getRowCount() == 0) {
                runButton.setEnabled(false);
            } else {
                table.setRowSelectionInterval(0, 0);
            }

            table.getTableHeader().setFont(new Font(AppletConfig.CONFIG_DIALOG_FONT.getValue(), AppletConfig.CONFIG_DIALOG_FONT_STYLE.getValueInt(), AppletConfig.CONFIG_DIALOG_FONT_SIZE.getValueInt()));
            table.setFont(new Font(AppletConfig.CONFIG_DIALOG_FONT.getValue(), AppletConfig.CONFIG_DIALOG_FONT_STYLE.getValueInt(), AppletConfig.CONFIG_DIALOG_FONT_SIZE.getValueInt()));
            table.setBounds(AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_X.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_Y.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_WIDTH.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_HEIGHT.getValueInt());
            table.setMinimumSize(new Dimension(AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_WIDTH.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_HEIGHT.getValueInt()));
            table.setRowHeight(AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_ROW_HEIGHT.getValueInt());
            table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);

            // Dimensiona cada coluna separadamente
            TableColumn tc1 = table.getColumnModel().getColumn(0);
            tc1.setPreferredWidth(200);

            TableColumn tc2 = table.getColumnModel().getColumn(1);
            tc2.setPreferredWidth(140);

            TableColumn tc3 = table.getColumnModel().getColumn(2);
            tc3.setPreferredWidth(140);

            TableColumn tc4 = table.getColumnModel().getColumn(3);
            tc4.setPreferredWidth(250);

            // Configura o Painel
            scrollPane.setBounds(AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_X.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_Y.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_WIDTH.getValueInt(), AppletConfig.CONFIG_DIALOG_TABLE_CERTIFICATES_HEIGHT.getValueInt());
            scrollPane.setViewportView(table);

            // botao Run
            runButton.setText(AppletConfig.LABEL_DIALOG_BUTTON_RUN.getValue());
            runButton.setFont(new Font(AppletConfig.CONFIG_DIALOG_FONT.getValue(), AppletConfig.CONFIG_DIALOG_FONT_STYLE.getValueInt(), AppletConfig.CONFIG_DIALOG_FONT_SIZE.getValueInt()));
            runButton.setBounds(new Rectangle(AppletConfig.CONFIG_DIALOG_BUTTON_RUN_X.getValueInt(), AppletConfig.CONFIG_DIALOG_BUTTON_RUN_Y.getValueInt(), AppletConfig.CONFIG_DIALOG_BUTTON_RUN_WIDTH.getValueInt(), AppletConfig.CONFIG_DIALOG_BUTTON_RUN_HEIGHT.getValueInt()));

            // botao Cancel
            cancelButton.setText(AppletConfig.LABEL_DIALOG_BUTTON_CANCEL.getValue());
            cancelButton.setFont(new Font(AppletConfig.CONFIG_DIALOG_FONT.getValue(), AppletConfig.CONFIG_DIALOG_FONT_STYLE.getValueInt(), AppletConfig.CONFIG_DIALOG_FONT_SIZE.getValueInt()));
            cancelButton.setBounds(new Rectangle(AppletConfig.CONFIG_DIALOG_BUTTON_CANCEL_X.getValueInt(), AppletConfig.CONFIG_DIALOG_BUTTON_CANCEL_Y.getValueInt(), AppletConfig.CONFIG_DIALOG_BUTTON_CANCEL_WIDTH.getValueInt(), AppletConfig.CONFIG_DIALOG_BUTTON_CANCEL_HEIGHT.getValueInt()));

            this.add(scrollPane, null);
            this.add(runButton, null);
            this.add(cancelButton, null);

        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    /**
     * Permite acesso ao objeto Table contendo a lista de certificados digitais
     *
     * @return A lista de certificados digitais
     */
    public JTable getTable() {
        return this.table;
    }

    /**
     *
     * @param key
     */
    public void addScrollPaneLineKeyListener(KeyListener key) {
        table.addKeyListener(key);
    }

    /**
     * Adicionar um ActionListener ao botao "Run"
     *
     * @param action ActionListener
     */
    public void addButtonRunActionListener(ActionListener action) {
        runButton.addActionListener(action);
    }

    /**
     * Adicionar um ActionListener ao botao "Cancel"
     *
     * @param action ActionListener
     */
    public void addButtonCancelActionListener(ActionListener action) {
        cancelButton.addActionListener(action);
    }

    /**
     * Retorna o keystore do dispositivo a partir do valor de pin
     */
    public KeyStore getKeyStore() {
        try {
            Cursor hourGlassCursor = new Cursor(Cursor.WAIT_CURSOR);
            setCursor(hourGlassCursor);
            KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader();
            loader.setCallbackHandler(new PinCallbackHandler());
            keystore = loader.getKeyStore();
            loaded = true;
            return keystore;
        } catch (DriverNotAvailableException e) {
            showError(AppletConfig.MESSAGE_ERROR_DRIVER_NOT_AVAILABLE.getValue());
        } catch (PKCS11NotFoundException e) {
            showError(AppletConfig.MESSAGE_ERROR_PKCS11_NOT_FOUND.getValue());
        } catch (CertificateValidatorException e) {
            showError(AppletConfig.MESSAGE_ERROR_LOAD_TOKEN.getValue());
        } catch (InvalidPinException e) {
            showError(AppletConfig.MESSAGE_ERROR_INVALID_PIN.getValue());
        } catch (KeyStoreLoaderException ke) {
            showError(ke.getMessage());
        } catch (Exception ex) {
            showError(AppletConfig.MESSAGE_ERROR_UNEXPECTED.getValue());
        } finally {
            Cursor hourGlassCursos = new Cursor(Cursor.DEFAULT_CURSOR);
            setCursor(hourGlassCursos);
        }
        return null;
    }

    /**
     * Retorna o alias
     *
     * @return
     */
    public String getAlias() {
        if (table.getModel().getRowCount() != 0) {
            int row = table.getSelectedRow();
            Item item = (Item) table.getModel().getValueAt(row, 0);
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
    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, AppletConfig.LABEL_DIALOG_OPTION_PANE_TITLE.getValue(), JOptionPane.ERROR_MESSAGE);
    }

    /**
     * Retorna o botao run
     *
     * @return
     */
    public JButton getRunButton() {
        return runButton;
    }

    /**
     * Retorna as dimensoes padroes do panel
     *
     * @return
     */
    public Dimension getDimension() {
        return new Dimension(AppletConfig.CONFIG_DIALOG_DIMENSION_WIDTH.getValueInt(), AppletConfig.CONFIG_DIALOG_DIMENSION_HEIGHT.getValueInt());
    }

    public int getCertificatesCount() {
        return table.getRowCount();
    }
}
