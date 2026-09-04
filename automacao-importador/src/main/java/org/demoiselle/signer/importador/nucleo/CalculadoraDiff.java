package org.demoiselle.signer.importador.nucleo;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.demoiselle.signer.importador.dominio.AtribuicaoAlias;
import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.ConflitoResolvido;
import org.demoiselle.signer.importador.dominio.DiffKeystore;
import org.demoiselle.signer.importador.dominio.ResultadoDedup;

/**
 * Calculo puro do diff entre o keystore antes e depois de uma persistencia.
 *
 * <p>Funcao pura (sem IO), deterministica e que nao muta as entradas. Os conjuntos
 * de adicionadas/removidas sao calculados pela identidade {@code (subject, serial)}
 * (via {@link Certificado#identidade()}) e ordenados de forma estavel por identidade,
 * para produzir relatorios reprodutiveis. Listas nulas sao tratadas como vazias.</p>
 */
public final class CalculadoraDiff {

    private CalculadoraDiff() {
    }

    /**
     * Calcula o {@link DiffKeystore} entre o snapshot anterior e posterior a gravacao.
     *
     * <ul>
     *   <li>adicionadas = {@code depois \ antes} por identidade {@code (subject, serial)};
     *       quando {@code antes} e vazio (primeira publicacao), todas as de {@code depois}
     *       contam como adicionadas.</li>
     *   <li>removidas = {@code antes \ depois} por identidade {@code (subject, serial)}.</li>
     *   <li>descartadasDedup = duplicatas removidas pela deduplicacao
     *       ({@link ResultadoDedup#descartadosDuplicata()}).</li>
     *   <li>conflitosResolvidos = {@link ResultadoDedup#conflitosCase()}.</li>
     *   <li>aliasesRenomeados = atribuicoes cujo {@code aliasFinal} difere do
     *       {@code aliasOriginal} (case-insensitive), via {@link AtribuicaoAlias#renomeado()}.</li>
     *   <li>inalterado = {@code true} quando todos os conjuntos acima estao vazios.</li>
     * </ul>
     *
     * @param antes          certificados presentes no keystore antes da gravacao (nulo tratado como vazio)
     * @param depois         certificados presentes no keystore apos a gravacao (nulo tratado como vazio)
     * @param resultadoDedup resultado da deduplicacao (nulo tratado como sem descartes/conflitos)
     * @param atribuicoes    atribuicoes de alias (nulo tratado como vazio)
     * @return o {@link DiffKeystore} correspondente
     */
    public static DiffKeystore calcular(List<Certificado> antes,
                                        List<Certificado> depois,
                                        ResultadoDedup resultadoDedup,
                                        List<AtribuicaoAlias> atribuicoes) {
        List<Certificado> listaAntes = antes == null ? List.of() : antes;
        List<Certificado> listaDepois = depois == null ? List.of() : depois;

        Set<String> idsAntes = identidades(listaAntes);
        Set<String> idsDepois = identidades(listaDepois);

        List<Certificado> adicionadas = diferenca(listaDepois, idsAntes);
        List<Certificado> removidas = diferenca(listaAntes, idsDepois);

        List<Certificado> descartadasDedup = resultadoDedup == null || resultadoDedup.descartadosDuplicata() == null
                ? List.of()
                : List.copyOf(resultadoDedup.descartadosDuplicata());

        List<ConflitoResolvido> conflitosResolvidos = resultadoDedup == null || resultadoDedup.conflitosCase() == null
                ? List.of()
                : List.copyOf(resultadoDedup.conflitosCase());

        List<AtribuicaoAlias> aliasesRenomeados = new ArrayList<>();
        if (atribuicoes != null) {
            for (AtribuicaoAlias a : atribuicoes) {
                if (a != null && a.renomeado()) {
                    aliasesRenomeados.add(a);
                }
            }
        }

        boolean inalterado = adicionadas.isEmpty()
                && removidas.isEmpty()
                && descartadasDedup.isEmpty()
                && conflitosResolvidos.isEmpty()
                && aliasesRenomeados.isEmpty();

        return new DiffKeystore(
                adicionadas,
                removidas,
                descartadasDedup,
                conflitosResolvidos,
                List.copyOf(aliasesRenomeados),
                inalterado);
    }

    /** Conjunto das identidades {@code (subject, serial)} presentes na lista. */
    private static Set<String> identidades(List<Certificado> certs) {
        Set<String> ids = new LinkedHashSet<>();
        for (Certificado c : certs) {
            ids.add(c.identidade());
        }
        return ids;
    }

    /**
     * Retorna os certificados de {@code origem} cuja identidade nao esta em
     * {@code idsExcluir}, deduplicados por identidade e ordenados de forma estavel
     * por identidade.
     */
    private static List<Certificado> diferenca(List<Certificado> origem, Set<String> idsExcluir) {
        List<Certificado> resultado = new ArrayList<>();
        Set<String> jaIncluidos = new LinkedHashSet<>();
        for (Certificado c : origem) {
            String id = c.identidade();
            if (!idsExcluir.contains(id) && jaIncluidos.add(id)) {
                resultado.add(c);
            }
        }
        resultado.sort((a, b) -> a.identidade().compareTo(b.identidade()));
        return List.copyOf(resultado);
    }
}
