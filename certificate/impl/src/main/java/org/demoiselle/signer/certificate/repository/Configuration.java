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
package org.demoiselle.signer.certificate.repository;

import java.util.logging.Logger;

public class Configuration {

    /**
     * Chave do System para definir modo online ou offline
     */
    public static final String MODE_ONLINE = "security.certificate.repository.online";

    /**
     * Chave do System para definir local de armazenamento do arquivo de index
     * das crls
     */
    public static final String CRL_INDEX = "security.certificate.repository.crl.index";

    /**
     * Chave do System para definir local de armazenamento do arquivo de index
     * das crls
     */
    public static final String CRL_PATH = "security.certificate.repository.crl.path";
    public static Configuration instance = new Configuration();
    private static final Logger logger = Logger.getLogger(Configuration.class.getName());

    /**
     * Returna a instância única
     *
     * @return A instância
     */
    public static Configuration getInstance() {
        return instance;
    }

    private String crlIndex;
    private String crlPath;
    private boolean isOnline;

    /**
     * Verifica se há variavéis no System. Caso haja, seta nas variaveis de
     * classes do contrário usa os valores padrões
     */
    private Configuration() {
        String mode_online = (String) System.getProperties().get(MODE_ONLINE);
        if (mode_online == null || mode_online.isEmpty()) {
            setOnline(true);
        } else {
            setOnline(Boolean.valueOf(mode_online));
        }
        crlIndex = (String) System.getProperties().get(CRL_INDEX);
        if (crlIndex == null || crlIndex.isEmpty()) {
            setCrlIndex(".crl_index");
        }

        crlPath = (String) System.getProperties().get(CRL_PATH);
        if (crlPath == null || crlPath.equals("")) {
            setCrlPath("/tmp/crls");
        }
    }

    /**
     * Obtém o local onde está armazenado o arquivo de indice de crl
     *
     * @return O local do índice da crl
     */
    public String getCrlIndex() {
        return crlIndex;
    }

    public void setCrlIndex(String crlIndex) {
        this.crlIndex = crlIndex;
    }

    /**
     * Retorna se o repositório está no modo online ou offline
     *
     * @return se true (online) se false (offline)
     */
    public boolean isOnline() {
        return isOnline;
    }

    /**
     * Determina se a consulta ao repositório deve ser feita online ou offline
     *
     * @param isOnline True se acesso foi feito online, False em contrário.
     */
    public void setOnline(boolean isOnline) {
        this.isOnline = isOnline;
    }

    /**
     * Recupera o local onde esta armazenado o repositório de CRLs
     *
     * @return O caminho do armazenamento das CRLs
     */
    public String getCrlPath() {
        return crlPath;
    }

    /**
     * Configura o local onde será armazenado o repositório de CRLs
     *
     * @param crlPath O local do repositório
     */
    public void setCrlPath(String crlPath) {
        this.crlPath = crlPath;
    }

}
