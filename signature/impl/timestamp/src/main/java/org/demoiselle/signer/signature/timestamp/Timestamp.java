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
package org.demoiselle.signer.signature.timestamp;

import java.io.IOException;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Map;
import java.util.TimeZone;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author 07721825741
 */
public class Timestamp {

    private static final Logger logger = LoggerFactory.getLogger(Timestamp.class);

    private TimeStampToken timeStampToken = null;

    public Timestamp(TimeStampToken timeStampToken) {
        this.timeStampToken = timeStampToken;
    }

    /**
     * Retorna um fluxo de byte codificado ASN. 1 que representa o objeto
     * codificado.
     *
     * @return
     */
    public byte[] getCodificado() {
        try {
            return timeStampToken.getEncoded();
        } catch (IOException ex) {
            logger.info(ex.getMessage());
        }
        return null;
    }

    public String getPolitica() {
        return timeStampToken.getTimeStampInfo().getPolicy().toString();
    }

    public String getNumeroSerie() {
        return timeStampToken.getTimeStampInfo().getSerialNumber().toString();
    }

    public String getAlgoritmoDoHash() {
        return timeStampToken.getTimeStampInfo().getHashAlgorithm().getAlgorithm().toString();
    }

    public byte[] getMessageImprintDigest() {
        return timeStampToken.getTimeStampInfo().getMessageImprintDigest();
    }

    public String getMessageImprintDigestBase64() {
        return Base64.toBase64String(timeStampToken.getTimeStampInfo().getMessageImprintDigest());
    }

    public String getMessageImprintDigestHex() {
        return Hex.toHexString(timeStampToken.getTimeStampInfo().getMessageImprintDigest()).toUpperCase();
    }

    public Store getCRLs() {
        return timeStampToken.getCRLs();
    }

    public Store getCertificados() {
        return timeStampToken.getCertificates();
    }

    public Map getAtributosAssinados() {
        return timeStampToken.getSignedAttributes().toHashtable();
    }

    public Map getAtributosNaoAssinados() {
        return timeStampToken.getUnsignedAttributes().toHashtable();
    }

    /**
     * Retorna os dados da TSA (Time Stamping Authority)
     *
     * @return os atributos do certificado da TSA
     */
    public String getAutoridadeCarimboTempo() {
        return timeStampToken.getTimeStampInfo().getTsa().toString();
    }

    /**
     * Retorna o valor "nonce", ou retorna nulo se nao existir nenhum
     *
     * @return o valor "nonce"
     */
    public BigInteger getNonce() {
        return timeStampToken.getTimeStampInfo().getNonce();
    }

    public String getCarimbodeTempo() {
        SimpleDateFormat dateFormatGmt = new SimpleDateFormat("dd-MMM-yyyy HH:mm:ss:S z");
        dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormatGmt.format(timeStampToken.getTimeStampInfo().getGenTime());
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(0);
        builder.append("\n");
        builder.append("Data / hora......................: ").append(this.getCarimbodeTempo()).append("\n");
        builder.append("Politica.........................: ").append(this.getPolitica()).append("\n");
        builder.append("Numero de serie..................: ").append(this.getNumeroSerie()).append("\n");
        builder.append("Certificado TSA..................: ").append(this.getAutoridadeCarimboTempo()).append("\n");
        builder.append("Hash Algorithm...................: ").append(this.getAlgoritmoDoHash()).append("\n");
        builder.append("Message Imprint Digest (Hex).... : ").append(this.getMessageImprintDigestHex()).append("\n");
        builder.append("Message Imprint Digest (Base64)..: ").append(this.getMessageImprintDigestBase64()).append("\n");
        return builder.toString();
    }
}
