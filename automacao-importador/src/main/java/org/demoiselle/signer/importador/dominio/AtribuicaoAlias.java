package org.demoiselle.signer.importador.dominio;

/** Atribuicao de alias (entrada para o relatorio de persistencia). */
public record AtribuicaoAlias(
        Certificado cert,
        String aliasOriginal,
        String aliasFinal   // != aliasOriginal quando houve renomeacao
) {
    public boolean renomeado() { return !aliasOriginal.equalsIgnoreCase(aliasFinal); }
}
