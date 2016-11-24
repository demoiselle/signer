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
package org.demoiselle.signer.signature.timestamp.utils;

import org.demoiselle.signer.signature.core.exception.CertificateCoreException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class Utils {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Utils.class);

    /**
     * Efetua a conversao para Big Endian de acordo com a especificacao RFC 3161
     *
     * @param valor
     * @return
     */
    public static byte[] intToByteArray(int valor) {
        byte buffer[] = new byte[4];

        // PROTOCOLO RFC 3161 - formato big-endian da JVM
        buffer[0] = (byte) (valor >> 24 & 0xff);
        buffer[1] = (byte) (valor >> 16 & 0xff);
        buffer[2] = (byte) (valor >> 8 & 0xff);
        buffer[3] = (byte) (valor & 0xff);

        return buffer;
    }

    /**
     * Carrega o conteudo de um arquivo do disco
     *
     * @param arquivo Caminho do arquivo
     * @return Os bytes do arquivo
     */
    public static byte[] readContent(String arquivo) throws CertificateCoreException {
        try {
            File file = new File(arquivo);
            InputStream is = new FileInputStream(file);
            byte[] result = new byte[(int) file.length()];
            is.read(result);
            is.close();
            return result;
        } catch (FileNotFoundException ex) {
            throw new CertificateCoreException(ex.getMessage(), ex.getCause());
        } catch (IOException ex) {
            throw new CertificateCoreException(ex.getMessage(), ex.getCause());
        }
    }

    /**
     * Escreve um conjunto de bytes em disco
     *
     * @param conteudo O conteudo a ser escrito em disco
     * @param arquivo O caminho e nome do arquivo
     */
    public static void writeContent(byte[] conteudo, String arquivo) throws CertificateCoreException {
        try {
            File file = new File(arquivo);
            OutputStream os = new FileOutputStream(file);
            os.write(conteudo);
            os.flush();
            os.close();
        } catch (IOException ex) {
            throw new CertificateCoreException(ex.getMessage(), ex.getCause());
        }
    }
}
