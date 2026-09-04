package org.demoiselle.signer.importador.nucleo;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Calculo puro das cadeias HOM faltantes (Req 3.5).
 *
 * <p>Retorna exatamente as fontes HOM esperadas que NAO estao presentes na
 * Staging, isto e, o conjunto {@code esperadas \ presentes}. A funcao e pura,
 * deterministica e sem IO: preserva a ordem de {@code esperadas} e remove
 * duplicatas de forma estavel (mantendo a primeira ocorrencia).</p>
 *
 * <p>Nota para o orquestrador: o design posiciona {@code faltantes} como um
 * metodo de {@code nucleo.DetectorInconsistencias}. Esta classe utilitaria
 * separada existe apenas para evitar conflito de edicao com a Task 3.1, que
 * cria {@code DetectorInconsistencias}. Recomenda-se consolidar este metodo em
 * {@code DetectorInconsistencias} apos a Task 3.1 ser aplicada.</p>
 */
public final class CalculadoraFaltantes {

    private CalculadoraFaltantes() {
    }

    /**
     * Calcula as fontes HOM esperadas que nao estao presentes.
     *
     * @param esperadas fontes HOM esperadas (pode ser nulo, tratado como vazio)
     * @param presentes fontes presentes na Staging (pode ser nulo, tratado como vazio)
     * @return lista das esperadas ausentes, na ordem de {@code esperadas}, sem
     *         duplicatas (primeira ocorrencia preservada)
     */
    public static List<String> faltantes(Collection<String> esperadas, Collection<String> presentes) {
        if (esperadas == null || esperadas.isEmpty()) {
            return new ArrayList<>();
        }

        Set<String> presentesSet = new LinkedHashSet<>();
        if (presentes != null) {
            presentesSet.addAll(presentes);
        }

        Set<String> vistos = new LinkedHashSet<>();
        List<String> resultado = new ArrayList<>();
        for (String esperada : esperadas) {
            if (presentesSet.contains(esperada)) {
                continue;
            }
            if (vistos.add(esperada)) {
                resultado.add(esperada);
            }
        }
        return resultado;
    }
}
