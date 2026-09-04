package org.demoiselle.signer.importador.relatorio;

import java.util.List;

import org.demoiselle.signer.importador.dominio.AtribuicaoAlias;
import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.ConflitoResolvido;
import org.demoiselle.signer.importador.dominio.DiffKeystore;

/**
 * Builder puro do Relatorio_Persistencia. A partir de um {@link DiffKeystore},
 * monta um texto legivel listando cadeias adicionadas e removidas (subject +
 * serial), certificados descartados por deduplicacao, conflitos de case
 * resolvidos (mantido + descartados) e aliases renomeados (original + final).
 * Quando o diff indica {@code inalterado}, o texto declara explicitamente que
 * o Keystore_Final permaneceu inalterado.
 *
 * <p>Funcao pura e deterministica, sem IO. Este builder e chamado apenas apos
 * uma gravacao bem-sucedida; a decisao de chama-lo (ou nao, em rollback) cabe
 * ao ComandoPersistir, nao a este builder (Req 10.1, 10.8).
 */
public final class RelatorioPersistenciaBuilder {

    private RelatorioPersistenciaBuilder() {
    }

    /**
     * Constroi o texto do Relatorio_Persistencia a partir do diff informado.
     *
     * @param diff diferenca calculada entre o keystore antes e depois
     * @return o relatorio como texto legivel
     */
    public static String construir(DiffKeystore diff) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Relatorio de Persistencia ===\n");

        if (diff.inalterado()) {
            sb.append("O Keystore_Final permaneceu inalterado.\n");
            return sb.toString();
        }

        // Req 10.2 - cadeias adicionadas
        List<Certificado> adicionadas = diff.adicionadas();
        sb.append("Cadeias adicionadas (").append(adicionadas.size()).append("):\n");
        if (adicionadas.isEmpty()) {
            sb.append("  (nenhuma)\n");
        } else {
            for (Certificado c : adicionadas) {
                sb.append("  - ").append(descreve(c)).append('\n');
            }
        }

        // Req 10.3 - cadeias removidas
        List<Certificado> removidas = diff.removidas();
        sb.append("Cadeias removidas (").append(removidas.size()).append("):\n");
        if (removidas.isEmpty()) {
            sb.append("  (nenhuma)\n");
        } else {
            for (Certificado c : removidas) {
                sb.append("  - ").append(descreve(c)).append('\n');
            }
        }

        // Req 10.4 - descartados por deduplicacao
        List<Certificado> descartadasDedup = diff.descartadasDedup();
        sb.append("Certificados descartados por deduplicacao (")
                .append(descartadasDedup.size()).append("):\n");
        if (descartadasDedup.isEmpty()) {
            sb.append("  (nenhum)\n");
        } else {
            for (Certificado c : descartadasDedup) {
                sb.append("  - ").append(descreve(c)).append('\n');
            }
        }

        // Req 10.5 - conflitos de case resolvidos
        List<ConflitoResolvido> conflitos = diff.conflitosResolvidos();
        sb.append("Conflitos de case resolvidos (").append(conflitos.size()).append("):\n");
        if (conflitos.isEmpty()) {
            sb.append("  (nenhum)\n");
        } else {
            for (ConflitoResolvido conflito : conflitos) {
                sb.append("  - CN ").append(conflito.cnNorm()).append(":\n");
                sb.append("      mantido: ").append(descreve(conflito.mantido())).append('\n');
                List<Certificado> descartados = conflito.descartados();
                if (descartados.isEmpty()) {
                    sb.append("      descartados: (nenhum)\n");
                } else {
                    for (Certificado c : descartados) {
                        sb.append("      descartado: ").append(descreve(c)).append('\n');
                    }
                }
            }
        }

        // Req 10.6 - aliases renomeados
        List<AtribuicaoAlias> renomeados = diff.aliasesRenomeados();
        sb.append("Aliases renomeados (").append(renomeados.size()).append("):\n");
        if (renomeados.isEmpty()) {
            sb.append("  (nenhum)\n");
        } else {
            for (AtribuicaoAlias a : renomeados) {
                sb.append("  - ").append(a.aliasOriginal())
                        .append(" -> ").append(a.aliasFinal()).append('\n');
            }
        }

        return sb.toString();
    }

    /** Descreve um certificado por subject e serial. */
    private static String descreve(Certificado c) {
        return "subject=" + c.subject() + ", serial=" + c.serial();
    }
}
