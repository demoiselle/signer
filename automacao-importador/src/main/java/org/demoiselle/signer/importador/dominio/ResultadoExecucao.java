package org.demoiselle.signer.importador.dominio;

/** Resultado agregado para decisao de exit code e mensagem final. */
public record ResultadoExecucao(
        String processo,   // "baixar" | "persistir"
        int numeroFalhas,
        String mensagem
) {
    public boolean houveFalha() { return numeroFalhas > 0; }
}
