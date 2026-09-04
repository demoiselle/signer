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

package org.demoiselle.signer.policy.impl.cades;

/**
 * Enumerates all validation message codes used during signature verification.
 * <p>
 * Each constant maps to a message key in the {@code signer_core_messages.properties} bundle.
 * This allows callers to handle validation results programmatically without
 * coupling to the localized message text.
 *
 * @since 4.6.3
 */
public enum ValidationMessageCode {

    INVALID_BYTES_PKCS7("error.invalid.bytes.pkcs7"),
    INVALID_SIGNATURE("error.invalid.signature"),
    CRL_NOT_ACCESS("error.crl.not.access"),
    CERTIFICATE_PERIOD_EXPIRED("error.certificate.out.date"),
    SIGNATURE_MISMATCH("error.signature.mismatch"),
    SIGNATURE_MISMATCH_DIGEST("error.signature.mismatch.digest"),
    SIGNATURE_INVALID("error.signature.invalid"),
    CONTENT_NOT_DATA("error.content.not.data"),
    PKCS7_ATTRIBUTE_NOT_FOUND("error.pcks7.attribute.not.found"),
    SIGNED_ATTRIBUTE_TABLE_NOT_FOUND("error.signed.attribute.table.not.found"),
    SIGNED_ATTRIBUTE_NOT_FOUND("error.signed.attribute.not.found"),
    UNSIGNED_ATTRIBUTE_TABLE_NOT_FOUND("error.unsigned.attribute.table.not.found"),
    UNSIGNED_ATTRIBUTE_NOT_FOUND("error.unsigned.attribute.not.found"),
    POLICY_NOT_FOUND("error.policy.on.component.not.found"),
    TIMESTAMP_VALIDATION_FAILED("error.xml.invalid.signature.timestamp"),
    RFC5035_NO_CERTID("error.rfc5035.no.certid"),
    RFC5035_UNKNOWN_ALGORITHM("error.rfc5035.unknown.algorithm"),
    RFC5035_HASH_MISMATCH("error.rfc5035.hash.mismatch"),
    RFC5035_VALIDATION_FAILED("error.rfc5035.validation.failed"),
    RFC2634_HASH_MISMATCH("warn.rfc2634.hash.mismatch"),
    RFC2634_VALIDATION_FAILED("warn.rfc2634.validation.failed"),
    CERTIFICATE_CHAIN_FAILED("error.get.chain"),

    // Validacao de consistencia do hash da politica (Nota Tecnica 4/2026 ITI)
    POLICY_HASH_SIZE_MISMATCH("error.policy.hash.size.mismatch"),
    POLICY_HASH_UNKNOWN_ALGORITHM("warn.policy.hash.unknown.algorithm");



    private final String messageKey;

    ValidationMessageCode(String messageKey) {
        this.messageKey = messageKey;
    }

    /**
     * @return the message key used in the resource bundle
     */
    public String getMessageKey() {
        return messageKey;
    }

    /**
     * Finds a ValidationMessageCode by its message key.
     *
     * @param messageKey the resource bundle key
     * @return the matching enum constant, or {@code null} if not found
     */
    public static ValidationMessageCode fromMessageKey(String messageKey) {
        for (ValidationMessageCode code : values()) {
            if (code.messageKey.equals(messageKey)) {
                return code;
            }
        }
        return null;
    }
}
