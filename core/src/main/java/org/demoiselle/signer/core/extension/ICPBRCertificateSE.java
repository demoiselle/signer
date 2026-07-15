/*
 * Demoiselle Framework
 * Copyright (C) 2026 SERPRO
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
 */

package org.demoiselle.signer.core.extension;

import org.demoiselle.signer.core.oid.OID_2_16_76_1_4_5_1;

/**
 * Implemented Class for ICP-BRASIL (Resolução 211)
 * "SELO ELETRONICO" Certificates.
 *
 * @see ICPBRSubjectAlternativeNames
 */
public class ICPBRCertificateSE {

    private String cnpj;
    private OID_2_16_76_1_4_5_1 oID_2_16_76_1_4_5_1;

    public ICPBRCertificateSE(String cnpj, OID_2_16_76_1_4_5_1 oidAR) {
        this.cnpj = cnpj;
        this.oID_2_16_76_1_4_5_1 = oidAR;
    }

    public ICPBRCertificateSE(String cnpj) {
        this(cnpj, null);
    }

    /**
     * @return Corporate name in the the Brazilian IRS's Bussiness Company Registry Number called CNPJ
     */
    public String getCNPJ() {
        return cnpj;
    }

    /**
     * @return CNPJ da Autoridade de Registro (AR)
     */
    public String getCnpjAR() {
        return oID_2_16_76_1_4_5_1 != null ? oID_2_16_76_1_4_5_1.getCnpjAR() : null;
    }
}
