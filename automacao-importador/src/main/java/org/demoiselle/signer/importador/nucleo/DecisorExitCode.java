package org.demoiselle.signer.importador.nucleo;

import org.demoiselle.signer.importador.dominio.ResultadoExecucao;

/**
 * Decisao pura de codigo de saida a partir de um {@link ResultadoExecucao}.
 *
 * <p>Funcao pura, sem IO: nao chama {@code System.exit} nem imprime. Quem
 * chama (camada CLI) e responsavel por encerrar o processo com o codigo e por
 * imprimir a mensagem final.</p>
 */
public final class DecisorExitCode {

    /** Codigo de saida usado quando nao houve falha. */
    public static final int SUCESSO = 0;

    /** Codigo de saida usado quando houve ao menos uma falha. */
    public static final int FALHA = 1;

    private DecisorExitCode() {
    }

    /**
     * Retorna o codigo de saida correspondente ao resultado: {@code 0} se e
     * somente se nao houve falha ({@code numeroFalhas == 0}); caso contrario,
     * um valor diferente de zero.
     *
     * @param resultado resultado agregado da execucao (nao nulo)
     * @return {@code 0} em caso de sucesso; {@code != 0} em caso de falha
     */
    public static int codigo(ResultadoExecucao resultado) {
        return resultado.houveFalha() ? FALHA : SUCESSO;
    }

    /**
     * Monta a mensagem final deterministica que identifica o processo
     * ({@code baixar}/{@code persistir}) e a quantidade de falhas.
     *
     * <p>Exemplos: {@code "[baixar] concluido com 2 falha(s)"} ou
     * {@code "[persistir] concluido com sucesso"}.</p>
     *
     * @param resultado resultado agregado da execucao (nao nulo)
     * @return mensagem final formatada
     */
    public static String mensagemFinal(ResultadoExecucao resultado) {
        if (resultado.houveFalha()) {
            return "[" + resultado.processo() + "] concluido com " + resultado.numeroFalhas() + " falha(s)";
        }
        return "[" + resultado.processo() + "] concluido com sucesso";
    }
}
