package org.demoiselle.signer.importador.nucleo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.GrupoConflito;
import org.demoiselle.signer.importador.dominio.GrupoDuplicata;

/**
 * Deteccao pura de inconsistencias sobre uma lista de {@link Certificado}.
 *
 * <p>Todas as funcoes sao puras (sem IO), deterministicas e nao mutam a lista de
 * entrada. Os grupos retornados sao ordenados de forma estavel para facilitar
 * testes e a montagem de relatorios reprodutiveis.</p>
 *
 * <p>A semantica portada do {@code diagnostico-cadeia.go}:</p>
 * <ul>
 *   <li>Duplicata_Exata: certificados agrupados pela identidade {@code (serial, subject)};
 *       o grupo e uma duplicata quando contem mais de um membro.</li>
 *   <li>Conflito_De_Case: certificados agrupados por {@code cnNorm} (CN comparado de
 *       forma case-insensitive); o grupo e um conflito quando contem mais de uma
 *       grafia distinta de CN (por exemplo "Hom" vs "HOM"), como na deteccao do Go.</li>
 * </ul>
 */
public final class DetectorInconsistencias {

    private DetectorInconsistencias() {
    }

    /**
     * Detecta duplicatas exatas: agrupa os certificados pela identidade
     * {@code (serial, subject)} e retorna apenas os grupos com mais de um membro.
     *
     * <p>A ordem dos grupos e estavel: os grupos sao ordenados pela {@code identidade}
     * (ordem natural de {@link String}). Dentro de cada grupo, os membros preservam
     * a ordem de entrada.</p>
     *
     * @param certs lista de certificados (nao nula; membros nao nulos)
     * @return lista de {@link GrupoDuplicata}, cada um com tamanho maior que 1,
     *         ordenada de forma estavel por identidade
     */
    public static List<GrupoDuplicata> detectarDuplicatasExatas(List<Certificado> certs) {
        Map<String, List<Certificado>> porIdentidade = new LinkedHashMap<>();
        for (Certificado c : certs) {
            porIdentidade.computeIfAbsent(c.identidade(), k -> new ArrayList<>()).add(c);
        }

        List<GrupoDuplicata> grupos = new ArrayList<>();
        for (Map.Entry<String, List<Certificado>> e : porIdentidade.entrySet()) {
            if (e.getValue().size() > 1) {
                grupos.add(new GrupoDuplicata(e.getKey(), List.copyOf(e.getValue())));
            }
        }
        grupos.sort((a, b) -> a.identidade().compareTo(b.identidade()));
        return grupos;
    }

    /**
     * Detecta conflitos de case: agrupa os certificados por {@code cnNorm} e retorna
     * apenas os grupos que contem mais de uma grafia distinta de CN (mesmo
     * {@code cnNorm}, valores de {@code cn} diferentes).
     *
     * <p>Grupos onde todos os membros possuem exatamente a mesma grafia de CN nao sao
     * reportados como conflito de case (mesmo que sejam varios certificados): isso os
     * distingue de duplicatas exatas. A ordem dos grupos e estavel: ordenada por
     * {@code cnNorm}. Dentro de cada grupo, os membros preservam a ordem de entrada.</p>
     *
     * @param certs lista de certificados (nao nula; membros nao nulos)
     * @return lista de {@link GrupoConflito} com ao menos duas grafias distintas de CN,
     *         ordenada de forma estavel por {@code cnNorm}
     */
    public static List<GrupoConflito> detectarConflitosCase(List<Certificado> certs) {
        Map<String, List<Certificado>> porCnNorm = new LinkedHashMap<>();
        for (Certificado c : certs) {
            porCnNorm.computeIfAbsent(c.cnNorm(), k -> new ArrayList<>()).add(c);
        }

        List<GrupoConflito> grupos = new ArrayList<>();
        for (Map.Entry<String, List<Certificado>> e : porCnNorm.entrySet()) {
            if (temMaisDeUmaGrafia(e.getValue())) {
                grupos.add(new GrupoConflito(e.getKey(), List.copyOf(e.getValue())));
            }
        }
        grupos.sort((a, b) -> a.cnNorm().compareTo(b.cnNorm()));
        return grupos;
    }

    /**
     * Retorna {@code true} se o grupo contem ao menos duas grafias distintas de CN
     * (comparacao case-sensitive dos valores originais de {@code cn}).
     */
    private static boolean temMaisDeUmaGrafia(List<Certificado> grupo) {
        if (grupo.size() < 2) {
            return false;
        }
        String primeira = grupo.get(0).cn();
        for (Certificado c : grupo) {
            if (!java.util.Objects.equals(primeira, c.cn())) {
                return true;
            }
        }
        return false;
    }
}
