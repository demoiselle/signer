package org.demoiselle.signer.importador.io;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.demoiselle.signer.importador.dominio.Certificado;
import org.demoiselle.signer.importador.dominio.FalhaDownload;
import org.demoiselle.signer.importador.dominio.Manifest;
import org.demoiselle.signer.importador.dominio.Origem;
import org.demoiselle.signer.importador.nucleo.ParserCertificado;

/**
 * Orquestra o download das cadeias de PRODUÇÃO e HOMOLOGAÇÃO para a área de
 * <em>staging</em>, reutilizando as classes de IO já prontas: {@link ClienteHttp}
 * (timeout + retry), {@link ExpansorCertificados} (ZIP / p7b), {@link StagingWriter}
 * (layout + gravação DER + manifest) e {@link ParserCertificado} (normalização pura
 * do X.509).
 *
 * <p><strong>Fontes</strong> (portadas de {@code cadeias.go}, {@code main.go} e
 * {@code verificar-cadeias-v12.go}, configuráveis via {@link ConfigDownload}):</p>
 * <ul>
 *   <li><strong>PRO:</strong> o ZIP {@code ACcompactadox.zip} (expandido para certs) e o
 *       {@code .p7b} da TSA.</li>
 *   <li><strong>HOM:</strong> a listagem HTML da qual se extraem os links {@code .p7b}
 *       (regex {@code href="...p7b"}), e cada {@code .p7b} baixado individualmente.</li>
 * </ul>
 *
 * <p><strong>Fluxo por fonte:</strong> baixar via {@link ClienteHttp} (até 3 tentativas,
 * timeout de 30s); em sucesso, expandir para {@link X509Certificate}, gravar cada DER na
 * staging via {@link StagingWriter#gravar(Origem, String, byte[])} e montar o
 * {@link Certificado} via {@link ParserCertificado#paraCertificado}. Em falha definitiva
 * (após 3 tentativas ou conteúdo inválido), registrar uma {@link FalhaDownload} e
 * <em>continuar</em> com as demais fontes (a staging é preservada). Nenhum filtro por
 * validade é aplicado (Req 6.1).</p>
 *
 * <p>Para HOM, todos os nomes de {@code .p7b} encontrados na listagem são registrados em
 * {@link Manifest#homEsperadas()} para o cálculo posterior de faltantes (Req 3.5).</p>
 *
 * <p>Ao final, escreve o {@link Manifest} via
 * {@link StagingWriter#escreverManifest(Manifest)} e retorna um
 * {@link ResultadoDownloadStaging} com a contagem gravada e as falhas.</p>
 *
 * <p>Requirements: 2.1, 2.4, 2.5, 6.1, 7.1.</p>
 */
public final class ServicoDownload {

    /** Regex para extrair os links {@code .p7b} da listagem HTML (como no Go). */
    private static final Pattern PADRAO_HREF_P7B = Pattern.compile("href=\"([^\"]+\\.p7b)\"");

    private final ClienteHttp clienteHttp;
    private final ExpansorCertificados expansor;
    private final StagingWriter stagingWriter;
    private final ConfigDownload config;

    /**
     * Cria o serviço com as dependências de IO e a configuração de fontes.
     *
     * @param clienteHttp   cliente HTTP com timeout + retry (não nulo)
     * @param expansor      expansor de ZIP/p7b (não nulo)
     * @param stagingWriter escritor da staging (não nulo)
     * @param config        configuração das URLs de origem (não nula)
     */
    public ServicoDownload(ClienteHttp clienteHttp, ExpansorCertificados expansor,
            StagingWriter stagingWriter, ConfigDownload config) {
        this.clienteHttp = Objects.requireNonNull(clienteHttp, "clienteHttp");
        this.expansor = Objects.requireNonNull(expansor, "expansor");
        this.stagingWriter = Objects.requireNonNull(stagingWriter, "stagingWriter");
        this.config = Objects.requireNonNull(config, "config");
    }

    /**
     * Executa a orquestração completa: prepara a staging, baixa PRO e HOM, grava os
     * certificados e o manifest, e retorna o resultado.
     *
     * @return o resultado com o manifest gravado (contagem e falhas)
     */
    public ResultadoDownloadStaging executar() {
        stagingWriter.preparar();

        List<Certificado> certificados = new ArrayList<>();
        List<FalhaDownload> falhas = new ArrayList<>();

        // Cada fonte que será (re)gravada tem sua origem limpa antes, de modo que os
        // novos certificados substituam os anteriores daquela origem (Req 2.5).
        stagingWriter.limparOrigem(Origem.PRO);
        baixarPro(certificados, falhas);

        stagingWriter.limparOrigem(Origem.HOM);
        List<String> homEsperadas = baixarHom(certificados, falhas);

        Manifest manifest = new Manifest(Instant.now(), certificados, falhas, homEsperadas);
        stagingWriter.escreverManifest(manifest);
        return new ResultadoDownloadStaging(manifest);
    }

    /** Baixa e processa as fontes de PRODUÇÃO: o ZIP e o p7b da TSA. */
    private void baixarPro(List<Certificado> certificados, List<FalhaDownload> falhas) {
        // 1) ZIP compactado de produção.
        processarFonte(config.urlZipPro(), Origem.PRO, "ACcompactadox.zip", certificados, falhas,
                bytes -> expansor.expandirZip(bytes));

        // 2) p7b da TSA.
        processarFonte(config.urlTsaP7b(), Origem.PRO, nomeArquivoDaUrl(config.urlTsaP7b()),
                certificados, falhas, bytes -> expansor.expandirP7b(bytes));
    }

    /**
     * Baixa a listagem HOM, extrai todos os {@code .p7b} e processa cada um.
     *
     * @return a lista de identificadores {@code .p7b} esperados (todos os encontrados na
     *         listagem), para {@link Manifest#homEsperadas()}
     */
    private List<String> baixarHom(List<Certificado> certificados, List<FalhaDownload> falhas) {
        String urlListagem = config.urlListagemHom();
        ResultadoDownload listagem = clienteHttp.baixar(urlListagem);
        if (!listagem.sucesso()) {
            falhas.add(new FalhaDownload(urlListagem, Origem.HOM,
                    "listagem HOM inacessivel: " + listagem.motivo()));
            return List.of();
        }

        List<String> nomes = extrairNomesP7b(listagem.conteudo());
        if (nomes.isEmpty()) {
            falhas.add(new FalhaDownload(urlListagem, Origem.HOM,
                    "listagem HOM sem links .p7b"));
            return List.of();
        }

        String base = config.baseHom();
        for (String nome : nomes) {
            processarFonte(base + nome, Origem.HOM, nome, certificados, falhas,
                    bytes -> expansor.expandirP7b(bytes));
        }
        return nomes;
    }

    /**
     * Baixa uma fonte, expande seu conteúdo e grava cada certificado na staging.
     * Qualquer falha (download definitivamente falho ou conteúdo inválido) vira uma
     * {@link FalhaDownload} sem interromper as demais fontes.
     */
    private void processarFonte(String url, Origem origem, String fonteId,
            List<Certificado> certificados, List<FalhaDownload> falhas, Expansao expansao) {
        ResultadoDownload resultado = clienteHttp.baixar(url);
        if (!resultado.sucesso()) {
            falhas.add(new FalhaDownload(url, origem, "download falhou: " + resultado.motivo()));
            return;
        }

        List<X509Certificate> x509s;
        try {
            x509s = expansao.expandir(resultado.conteudo());
        } catch (RuntimeException e) {
            falhas.add(new FalhaDownload(url, origem, "conteudo invalido: " + mensagem(e)));
            return;
        }

        if (x509s.isEmpty()) {
            falhas.add(new FalhaDownload(url, origem, "conteudo sem certificados"));
            return;
        }

        try {
            int indice = 0;
            for (X509Certificate x509 : x509s) {
                String nomeArquivo = nomeCertificado(fonteId, indice++);
                byte[] der = x509.getEncoded();
                String caminhoRelativo = stagingWriter.gravar(origem, nomeArquivo, der);
                certificados.add(ParserCertificado.paraCertificado(x509, origem, fonteId, caminhoRelativo));
            }
        } catch (RuntimeException | java.security.cert.CertificateEncodingException e) {
            falhas.add(new FalhaDownload(url, origem, "falha ao gravar certificado: " + mensagem(e)));
        }
    }

    /**
     * Extrai os nomes de arquivo {@code .p7b} da listagem HTML via regex, descartando
     * duplicatas de nome (preservando a ordem de aparição), como no Go.
     */
    static List<String> extrairNomesP7b(byte[] html) {
        String texto = new String(html, java.nio.charset.StandardCharsets.ISO_8859_1);
        Matcher matcher = PADRAO_HREF_P7B.matcher(texto);
        Set<String> nomes = new LinkedHashSet<>();
        while (matcher.find()) {
            nomes.add(nomeArquivoDaUrl(matcher.group(1)));
        }
        return new ArrayList<>(nomes);
    }

    /** Reduz uma URL/caminho ao seu último segmento (o nome do arquivo). */
    private static String nomeArquivoDaUrl(String url) {
        String limpo = url;
        int fragmento = limpo.indexOf('#');
        if (fragmento >= 0) {
            limpo = limpo.substring(0, fragmento);
        }
        int query = limpo.indexOf('?');
        if (query >= 0) {
            limpo = limpo.substring(0, query);
        }
        int barra = limpo.lastIndexOf('/');
        return barra >= 0 ? limpo.substring(barra + 1) : limpo;
    }

    /**
     * Deriva um nome-base estável para o arquivo DER de um certificado dentro de uma
     * fonte. Remove a extensão {@code .p7b}/{@code .zip} da fonte e acrescenta o índice.
     */
    private static String nomeCertificado(String fonteId, int indice) {
        String base = fonteId;
        int ponto = base.lastIndexOf('.');
        if (ponto > 0) {
            base = base.substring(0, ponto);
        }
        if (base.isBlank()) {
            base = "cert";
        }
        return base + "_" + indice;
    }

    private static String mensagem(Throwable e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    /** Estratégia de expansão (ZIP ou p7b) aplicada aos bytes baixados. */
    @FunctionalInterface
    private interface Expansao {
        List<X509Certificate> expandir(byte[] bytes);
    }
}
