package org.demoiselle.signer.importador.io;

import java.util.Objects;

/**
 * Configuração das fontes de download orquestradas por {@link ServicoDownload}.
 *
 * <p>As URLs são configuráveis (originadas das opções de CLI {@code --url-*}), com os
 * valores DEFAULT portados da implementação Go anterior
 * ({@code automacao-importador/pkg/cadeias/cadeias.go} e {@code main.go}, mais
 * {@code verificar-cadeias-v12.go} para a listagem HOM):</p>
 *
 * <ul>
 *   <li>{@link #urlZipPro()} — ZIP compactado da cadeia de PRODUÇÃO
 *       ({@code ACcompactadox.zip}).</li>
 *   <li>{@link #urlTsaP7b()} — arquivo {@code .p7b} da cadeia da TSA (PRODUÇÃO).</li>
 *   <li>{@link #urlListagemHom()} — página HTML de HOMOLOGAÇÃO da qual se extraem os
 *       links {@code .p7b}.</li>
 * </ul>
 *
 * <p>A partir de {@link #urlListagemHom()} deriva-se a URL-base usada para baixar cada
 * {@code .p7b} individual: {@link #baseHom()} devolve a URL da listagem com barra final
 * garantida, à qual se concatena o nome do arquivo (comportamento equivalente ao Go
 * {@code BASE_URL + filename}).</p>
 *
 * <p>Requirements: 2.1 (fontes), 2.4/2.5 (falha por fonte).</p>
 */
public record ConfigDownload(
        String urlZipPro,
        String urlTsaP7b,
        String urlListagemHom
) {

    /** URL default do ZIP de produção ({@code ACcompactadox.zip}). */
    public static final String DEFAULT_URL_ZIP_PRO =
            "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip";

    /** URL default do {@code .p7b} da cadeia da TSA (produção). */
    public static final String DEFAULT_URL_TSA_P7B =
            "https://repositorio.serpro.gov.br/cadeias/acserproacfts.p7b";

    /** URL default da listagem HTML de homologação. */
    public static final String DEFAULT_URL_LISTAGEM_HOM =
            "https://repositoriohom.serpro.gov.br/cadeias/";

    public ConfigDownload {
        Objects.requireNonNull(urlZipPro, "urlZipPro");
        Objects.requireNonNull(urlTsaP7b, "urlTsaP7b");
        Objects.requireNonNull(urlListagemHom, "urlListagemHom");
    }

    /** Configuração com todas as URLs default. */
    public static ConfigDownload padrao() {
        return new ConfigDownload(DEFAULT_URL_ZIP_PRO, DEFAULT_URL_TSA_P7B, DEFAULT_URL_LISTAGEM_HOM);
    }

    /**
     * URL-base para baixar cada {@code .p7b} de homologação, garantindo a barra final.
     * Equivalente ao {@code BASE_URL} do Go.
     */
    public String baseHom() {
        return urlListagemHom.endsWith("/") ? urlListagemHom : urlListagemHom + "/";
    }
}
