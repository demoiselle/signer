package org.demoiselle.signer.importador.nucleo;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.ConflitoResolvido;
import org.demoiselle.signer.importador.dominio.ResultadoDedup;

/**
 * Deduplicacao pura de {@link Certificado}, com dois metodos: conservador e agressivo.
 *
 * <p>Todos os metodos sao puros (sem IO), deterministicos e nao mutam a lista de
 * entrada. Nenhum metodo aplica filtro por validade: {@code notBefore}/{@code notAfter}
 * nunca sao usados para descartar certificados, apenas como criterio de desempate no
 * metodo agressivo.</p>
 */
public final class Deduplicador {

    private Deduplicador() {
    }

    /**
     * Metodo conservador: remove apenas duplicatas exatas por identidade
     * {@code (serial, subject)}, mantendo a primeira ocorrencia de cada identidade na
     * ordem de entrada.
     *
     * <p>Certificados que constituem conflitos de case (mesmo {@code cnNorm}, grafias de
     * CN distintas) sao integralmente preservados: eles nao sao tocados. Nenhum
     * certificado e descartado por validade.</p>
     *
     * <p>No {@link ResultadoDedup} retornado: {@code mantidos} contem uma ocorrencia por
     * identidade (a primeira); {@code descartadosDuplicata} contem as ocorrencias extras
     * removidas (na ordem de entrada); {@code conflitosCase} fica sempre vazio.</p>
     *
     * @param certs lista de certificados (nao nula; membros nao nulos)
     * @return {@link ResultadoDedup} com mantidos e duplicatas exatas descartadas
     */
    public static ResultadoDedup conservador(List<Certificado> certs) {
        Set<String> vistos = new LinkedHashSet<>();
        List<Certificado> mantidos = new ArrayList<>();
        List<Certificado> descartados = new ArrayList<>();

        for (Certificado c : certs) {
            if (vistos.add(c.identidade())) {
                mantidos.add(c);
            } else {
                descartados.add(c);
            }
        }

        return new ResultadoDedup(List.copyOf(mantidos), List.copyOf(descartados), List.of());
    }

    /**
     * Metodo agressivo: agrupa os certificados por {@code cnNorm} (CN comparado de forma
     * case-insensitive) e mantem exatamente um por grupo, garantindo no maximo um
     * certificado por CN case-insensitive nos mantidos (ausencia de conflito de case).
     *
     * <p>Criterio de selecao dentro de cada grupo: mantem o de {@code notBefore} mais
     * recente; em empate no {@code notBefore} maximo, mantem o de menor indice de entrada
     * (desempate estavel). O {@code notBefore} e usado exclusivamente como criterio de
     * desempate, nunca como filtro por validade.</p>
     *
     * <p>No {@link ResultadoDedup} retornado: {@code mantidos} contem um certificado por
     * grupo de {@code cnNorm} (na ordem de entrada dos grupos); {@code conflitosCase}
     * contem um {@link ConflitoResolvido} por grupo que teve mais de um certificado,
     * com o mantido e os descartados daquele grupo. Como no metodo agressivo o descarte
     * e por agrupamento de CN (nao por identidade exata), os certificados removidos sao
     * reportados em {@code conflitosCase.descartados}, e {@code descartadosDuplicata}
     * permanece sempre vazio.</p>
     *
     * @param certs lista de certificados (nao nula; membros nao nulos)
     * @return {@link ResultadoDedup} com um mantido por cnNorm e os conflitos resolvidos
     */
    public static ResultadoDedup agressivo(List<Certificado> certs) {
        Map<String, List<Certificado>> porCnNorm = new LinkedHashMap<>();
        for (Certificado c : certs) {
            porCnNorm.computeIfAbsent(c.cnNorm(), k -> new ArrayList<>()).add(c);
        }

        List<Certificado> mantidos = new ArrayList<>();
        List<ConflitoResolvido> conflitos = new ArrayList<>();

        for (Map.Entry<String, List<Certificado>> e : porCnNorm.entrySet()) {
            List<Certificado> grupo = e.getValue();
            Certificado escolhido = grupo.get(0);
            for (int i = 1; i < grupo.size(); i++) {
                Certificado candidato = grupo.get(i);
                // Estritamente mais recente vence; empate no maximo mantem o de menor indice.
                if (candidato.notBefore().isAfter(escolhido.notBefore())) {
                    escolhido = candidato;
                }
            }
            mantidos.add(escolhido);

            if (grupo.size() > 1) {
                List<Certificado> descartados = new ArrayList<>();
                for (Certificado c : grupo) {
                    if (c != escolhido) {
                        descartados.add(c);
                    }
                }
                conflitos.add(new ConflitoResolvido(e.getKey(), escolhido, List.copyOf(descartados)));
            }
        }

        return new ResultadoDedup(List.copyOf(mantidos), List.of(), List.copyOf(conflitos));
    }
}
