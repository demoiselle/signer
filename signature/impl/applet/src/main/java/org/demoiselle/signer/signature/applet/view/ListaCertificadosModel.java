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
package org.demoiselle.signer.signature.applet.view;

import org.demoiselle.signer.signature.applet.tiny.Item;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.swing.table.AbstractTableModel;

public class ListaCertificadosModel extends AbstractTableModel {

    private Object[][] dados;

    private final String[] columnNames = {"Emitido Para", "Número de série", "Válido de", "Válido até", "Emitido Por"};

    @Override
    public int getRowCount() {
        if (dados != null) {
            return dados.length;
        } else {
            return 0;
        }
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return dados[rowIndex][columnIndex];
    }

    public void populate(KeyStore keystore) {
        try {

            if (keystore != null) {
                int linha = keystore.size();
                int coluna = columnNames.length;

                dados = new Object[linha][coluna];

                int ik = 0;
                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);

                    Item item = new Item(alias, certificate.getSubjectDN().getName(), certificate.getSerialNumber().toString(), certificate.getNotBefore(), certificate.getNotAfter(), certificate.getIssuerDN().getName());
                    dados[ik][0] = item;
                    dados[ik][1] = item.getSerialNumber();
                    dados[ik][2] = item.getInitDate();
                    dados[ik][3] = item.getEndDate();
                    dados[ik][4] = item.getIssuer();
                    ik++;
                }
                fireTableDataChanged();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }
}
