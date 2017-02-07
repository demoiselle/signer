/*
 * Demoiselle Framework
 * Copyright (C) 2017 SERPRO
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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import javax.swing.table.AbstractTableModel;
import org.demoiselle.signer.jnlp.tiny.Item;

/**
 * Extension for TableModel to show commons certificate attributes ( SubjectDN, NotBefore, NotAfter, IssuerDN)
*/
public class CertificateModel extends AbstractTableModel {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	private Object[][] data;
    private final String[] columnNames = {"Emitido Para", "Válido de", "Válido até", "Emitido Por"};

    @Override
    public int getRowCount() {
        if (data != null) {
            return data.length;
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
        return data[rowIndex][columnIndex];
    }

    public void populate(KeyStore keystore) {
        try {
            if (keystore != null) {
                int linha = keystore.size();
                int coluna = columnNames.length;

                data = new Object[linha][coluna];

                int ik = 0;
                Enumeration<String> aliases = keystore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    X509Certificate certificate = (X509Certificate) keystore.getCertificate(alias);

                    Item item = new Item(alias, certificate.getSubjectDN().getName(), certificate.getNotBefore(), certificate.getNotAfter(), certificate.getIssuerDN().getName());
                    data[ik][0] = item;
                    data[ik][1] = item.getInitDate();
                    data[ik][2] = item.getEndDate();
                    data[ik][3] = item.getIssuer();
                    ik++;
                }
                fireTableDataChanged();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

    }

}
