package org.demoiselle.signer.importador.nucleo;

import java.util.Locale;

/**
 * Decisao pura sobre gravar ou nao o Keystore_Final quando o fluxo combina
 * download e persistencia e ocorreram falhas de download (Req 7.2-7.5).
 *
 * <p>A gravacao so ocorre se e somente se nao houve falhas de download, ou
 * houve falhas mas existe TTY interativo e o operador respondeu explicitamente
 * "sim". O default e "nao": qualquer resposta que nao seja "sim"/"s"
 * (case-insensitive) conta como "nao". A ausencia de TTY forca "nao" quando ha
 * falhas.</p>
 *
 * <p>Funcao pura, sem IO: a deteccao de TTY ({@code System.console() == null})
 * e a leitura da resposta ficam na camada de IO que invoca este decisor,
 * passando o resultado por parametro.</p>
 */
public final class DecisorGravacao {

    private DecisorGravacao() {
    }

    /**
     * Decide se o Keystore_Final deve ser gravado.
     *
     * @param nFalhasDownload  quantidade de falhas de download registradas
     * @param temTty           {@code true} se ha TTY interativo disponivel
     * @param respostaOperador resposta do operador (pode ser nula); apenas
     *                         "sim" ou "s" (case-insensitive, ignorando espacos
     *                         nas bordas) equivalem a confirmacao
     * @return {@code true} se e somente se {@code nFalhasDownload == 0}, ou
     *         ({@code nFalhasDownload > 0} e {@code temTty} e a resposta
     *         equivale a "sim")
     */
    public static boolean deveGravar(int nFalhasDownload, boolean temTty, String respostaOperador) {
        if (nFalhasDownload == 0) {
            return true;
        }
        if (!temTty) {
            return false;
        }
        return respostaConfirma(respostaOperador);
    }

    /**
     * Interpreta a resposta do operador como confirmacao. Aceita apenas "sim" e
     * "s" (case-insensitive, ignorando espacos nas bordas); qualquer outra
     * entrada, incluindo nula ou vazia, conta como "nao".
     */
    private static boolean respostaConfirma(String respostaOperador) {
        if (respostaOperador == null) {
            return false;
        }
        String normalizada = respostaOperador.trim().toLowerCase(Locale.ROOT);
        return "sim".equals(normalizada) || "s".equals(normalizada);
    }
}
