package org.demoiselle.signer.importador.relatorio;

import java.util.ArrayList;
import java.util.List;

import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.FalhaDownload;
import org.demoiselle.signer.importador.dominio.GrupoConflito;
import org.demoiselle.signer.importador.dominio.GrupoDuplicata;
import org.demoiselle.signer.importador.dominio.Manifest;
import org.demoiselle.signer.importador.nucleo.CalculadoraFaltantes;
import org.demoiselle.signer.importador.nucleo.DetectorInconsistencias;

/**
 * Montagem pura do texto do Relatorio_Inconsistencias a partir de um {@link Manifest}.
 *
 * <p>A funcao {@link #construir(Manifest)} e pura (sem IO), deterministica e de ordem
 * estavel: a partir de um mesmo {@code Manifest} sempre produz exatamente o mesmo texto.
 * Reutiliza as funcoes puras de {@link DetectorInconsistencias} (duplicatas exatas e
 * conflitos de case) e {@link CalculadoraFaltantes} (cadeias HOM faltantes) sobre os
 * dados do manifest.</p>
 *
 * <p>O relatorio lista, nesta ordem (Req 3.1-3.6, 7.1):</p>
 * <ul>
 *   <li>falhas de download: recurso ({@link FalhaDownload#fonteId()}), origem e motivo;</li>
 *   <li>duplicatas exatas detectadas sobre {@code manifest.certificados()};</li>
 *   <li>conflitos de case detectados;</li>
 *   <li>cadeias HOM faltantes: {@code manifest.homEsperadas() \ fonteIds das cadeias HOM presentes}.</li>
 * </ul>
 *
 * <p>Quando nao ha nenhuma falha, duplicata, conflito de case nem faltante, o texto
 * indica explicitamente a ausencia de inconsistencias (Req 3.6).</p>
 */
public final class RelatorioInconsistenciasBuilder {

    private static final String NL = "\n";

    private RelatorioInconsistenciasBuilder() {
    }

    /**
     * Constroi o texto legivel do Relatorio_Inconsistencias.
     *
     * @param manifest manifest da Staging (nao nulo); listas internas nulas sao
     *                 tratadas como vazias
     * @return o relatorio como {@link String}, deterministico e de ordem estavel
     */
    public static String construir(Manifest manifest) {
        List<Certificado> certificados = manifest.certificados() != null
                ? manifest.certificados() : List.of();
        List<FalhaDownload> falhas = manifest.falhas() != null
                ? manifest.falhas() : List.of();
        List<String> homEsperadas = manifest.homEsperadas() != null
                ? manifest.homEsperadas() : List.of();

        List<GrupoDuplicata> duplicatas =
                DetectorInconsistencias.detectarDuplicatasExatas(certificados);
        List<GrupoConflito> conflitos =
                DetectorInconsistencias.detectarConflitosCase(certificados);
        List<String> faltantes =
                CalculadoraFaltantes.faltantes(homEsperadas, fonteIdsHom(certificados));

        StringBuilder sb = new StringBuilder();
        sb.append("Relatorio_Inconsistencias").append(NL);

        boolean semInconsistencias = falhas.isEmpty()
                && duplicatas.isEmpty()
                && conflitos.isEmpty()
                && faltantes.isEmpty();
        if (semInconsistencias) {
            sb.append("Nenhuma inconsistencia detectada.").append(NL);
            return sb.toString();
        }

        anexarFalhas(sb, falhas);
        anexarDuplicatas(sb, duplicatas);
        anexarConflitos(sb, conflitos);
        anexarFaltantes(sb, faltantes);
        return sb.toString();
    }

    private static void anexarFalhas(StringBuilder sb, List<FalhaDownload> falhas) {
        sb.append("Falhas de download (").append(falhas.size()).append("):").append(NL);
        for (FalhaDownload f : falhas) {
            sb.append("  - recurso=").append(f.fonteId())
              .append(", origem=").append(f.origem())
              .append(", motivo=").append(f.motivo())
              .append(NL);
        }
    }

    private static void anexarDuplicatas(StringBuilder sb, List<GrupoDuplicata> duplicatas) {
        sb.append("Duplicatas exatas (").append(duplicatas.size()).append("):").append(NL);
        for (GrupoDuplicata g : duplicatas) {
            sb.append("  - identidade=").append(g.identidade())
              .append(", ocorrencias=").append(g.membros().size())
              .append(NL);
        }
    }

    private static void anexarConflitos(StringBuilder sb, List<GrupoConflito> conflitos) {
        sb.append("Conflitos de case (").append(conflitos.size()).append("):").append(NL);
        for (GrupoConflito g : conflitos) {
            sb.append("  - cnNorm=").append(g.cnNorm())
              .append(", grafias=[").append(grafias(g.certificados())).append("]")
              .append(NL);
        }
    }

    private static void anexarFaltantes(StringBuilder sb, List<String> faltantes) {
        sb.append("Cadeias HOM faltantes (").append(faltantes.size()).append("):").append(NL);
        for (String fonteId : faltantes) {
            sb.append("  - ").append(fonteId).append(NL);
        }
    }

    /**
     * Extrai os {@code fonteId} das cadeias HOM presentes no manifest, na ordem de
     * entrada. Sao esses identificadores que representam as fontes HOM ja presentes
     * na Staging, comparadas contra {@code homEsperadas} para o calculo de faltantes.
     */
    private static List<String> fonteIdsHom(List<Certificado> certificados) {
        List<String> fontes = new ArrayList<>();
        for (Certificado c : certificados) {
            if (c.origem() == org.demoiselle.signer.importador.dominio.Origem.HOM) {
                fontes.add(c.fonteId());
            }
        }
        return fontes;
    }

    /**
     * Concatena as grafias distintas de CN de um grupo de conflito, na ordem de
     * primeira ocorrencia, separadas por ", ".
     */
    private static String grafias(List<Certificado> certificados) {
        List<String> distintas = new ArrayList<>();
        for (Certificado c : certificados) {
            if (!distintas.contains(c.cn())) {
                distintas.add(c.cn());
            }
        }
        return String.join(", ", distintas);
    }
}
