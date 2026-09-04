package org.demoiselle.signer.importador.cli;

import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

import org.demoiselle.signer.importador.dominio.Manifest;
import org.demoiselle.signer.importador.dominio.ResultadoExecucao;
import org.demoiselle.signer.importador.io.ClienteHttp;
import org.demoiselle.signer.importador.io.ConfigDownload;
import org.demoiselle.signer.importador.io.ExpansorCertificados;
import org.demoiselle.signer.importador.io.ResultadoDownloadStaging;
import org.demoiselle.signer.importador.io.ServicoDownload;
import org.demoiselle.signer.importador.io.StagingWriter;
import org.demoiselle.signer.importador.nucleo.DecisorExitCode;
import org.demoiselle.signer.importador.relatorio.RelatorioInconsistenciasBuilder;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Subcomando {@code baixar}: baixa todas as cadeias de PRODUCAO e HOMOLOGACAO para a
 * area de <em>staging</em> em disco e emite o Relatorio_Inconsistencias, <strong>sem
 * tocar no Keystore_Final</strong>.
 *
 * <p><strong>Escopo (Task 14.1).</strong> Orquestra as classes de IO/nucleo/relatorio
 * ja prontas: monta um {@link ConfigDownload} a partir das opcoes de CLI, instancia
 * {@link StagingWriter}, {@link ExpansorCertificados}, {@link ClienteHttp} (transporte
 * padrao) e {@link ServicoDownload}, executa o download para a staging, emite o
 * Relatorio_Inconsistencias antes de qualquer persistencia e traduz o resultado em
 * exit code via {@link DecisorExitCode}.</p>
 *
 * <p><strong>Fluxo de {@link #call()}:</strong></p>
 * <ol>
 *   <li>Monta {@link ConfigDownload} com as URLs de origem ({@code --url-*}).</li>
 *   <li>Instancia {@link StagingWriter} (raiz {@code --staging}),
 *       {@link ExpansorCertificados}, {@link ClienteHttp#comTransportePadrao()} e
 *       {@link ServicoDownload}.</li>
 *   <li>Executa {@link ServicoDownload#executar()} &rarr;
 *       {@link ResultadoDownloadStaging} (contem o {@link Manifest}, a contagem gravada
 *       e as falhas).</li>
 *   <li>Emite o Relatorio_Inconsistencias via
 *       {@link RelatorioInconsistenciasBuilder#construir(Manifest)} no {@code stdout},
 *       <em>antes</em> de qualquer persistencia (Req 3.1).</li>
 *   <li>Reporta a contagem de certificados gravados na staging (Req 1.3).</li>
 *   <li>Monta um {@link ResultadoExecucao} a partir das falhas do manifest e retorna o
 *       exit code de {@link DecisorExitCode#codigo(ResultadoExecucao)} (Req 9.1, 9.2),
 *       imprimindo {@link DecisorExitCode#mensagemFinal(ResultadoExecucao)}.</li>
 * </ol>
 *
 * <p>O comando {@code baixar} <strong>nunca</strong> escreve, remove ou altera o
 * Keystore_Final: ele opera exclusivamente sobre a staging (Req 1.2, 2.2). As falhas de
 * download sao preservadas na staging e registradas no manifest pelo
 * {@link ServicoDownload} (Req 1.4, 7.1); este comando apenas as reflete no relatorio e
 * no exit code.</p>
 *
 * <p>Requisitos atendidos: 1.2, 1.3, 1.4, 2.1, 2.2, 3.1, 6.1, 7.1, 9.1, 9.2.</p>
 */
@Command(
        name = "baixar",
        description = {
                "Baixa todas as cadeias de PRODUCAO e HOMOLOGACAO para a Staging e emite "
                        + "o Relatorio_Inconsistencias, sem tocar no keystore.",
                "",
                "As URLs de origem e o diretorio de staging sao configuraveis (--url-*, "
                        + "--staging) com defaults sensatos, permitindo execucao como aplicacao "
                        + "autonoma, independente do layout do repositorio.",
                "",
                "Este comando nunca escreve, remove ou altera o keystore de destino."
        },
        mixinStandardHelpOptions = true,
        sortOptions = false
)
public class ComandoBaixar implements Callable<Integer> {

    /** Default sensato para o diretorio de staging (diretorio corrente). */
    static final String STAGING_DEFAULT = "staging";

    /** Identificador do processo, usado no {@link ResultadoExecucao} e mensagem final. */
    private static final String PROCESSO = "baixar";

    /** Diretorio de staging onde os certificados serao gravados (--staging). */
    @Option(
            names = {"--staging"},
            paramLabel = "<dir>",
            description = {
                    "Diretorio da Staging onde os certificados baixados serao gravados.",
                    "Default: ${DEFAULT-VALUE} (no diretorio corrente)."
            },
            defaultValue = STAGING_DEFAULT
    )
    private Path staging = Paths.get(STAGING_DEFAULT);

    /** URL do ZIP compactado da cadeia de PRODUCAO (--url-zip-pro). */
    @Option(
            names = {"--url-zip-pro"},
            paramLabel = "<url>",
            description = {
                    "URL do ZIP compactado da cadeia de PRODUCAO (ACcompactadox.zip).",
                    "Default: ${DEFAULT-VALUE}."
            },
            defaultValue = ConfigDownload.DEFAULT_URL_ZIP_PRO
    )
    private String urlZipPro = ConfigDownload.DEFAULT_URL_ZIP_PRO;

    /** URL do arquivo .p7b da cadeia da TSA (PRODUCAO) (--url-tsa-p7b). */
    @Option(
            names = {"--url-tsa-p7b"},
            paramLabel = "<url>",
            description = {
                    "URL do arquivo .p7b da cadeia da TSA (PRODUCAO).",
                    "Default: ${DEFAULT-VALUE}."
            },
            defaultValue = ConfigDownload.DEFAULT_URL_TSA_P7B
    )
    private String urlTsaP7b = ConfigDownload.DEFAULT_URL_TSA_P7B;

    /** URL da listagem HTML de HOMOLOGACAO da qual se extraem os .p7b (--url-listagem-hom). */
    @Option(
            names = {"--url-listagem-hom"},
            paramLabel = "<url>",
            description = {
                    "URL da listagem HTML de HOMOLOGACAO da qual se extraem os links .p7b.",
                    "Default: ${DEFAULT-VALUE}."
            },
            defaultValue = ConfigDownload.DEFAULT_URL_LISTAGEM_HOM
    )
    private String urlListagemHom = ConfigDownload.DEFAULT_URL_LISTAGEM_HOM;

    /**
     * Executa o processo {@code baixar}: baixa PRO e HOM para a staging, emite o
     * Relatorio_Inconsistencias e retorna o exit code (0 sse nao houve falha; != 0 caso
     * contrario). Nunca toca no keystore.
     *
     * @return o codigo de saida derivado de {@link DecisorExitCode}
     */
    @Override
    public Integer call() {
        PrintStream out = System.out;

        ConfigDownload config = new ConfigDownload(urlZipPro, urlTsaP7b, urlListagemHom);

        StagingWriter stagingWriter = new StagingWriter(staging);
        ExpansorCertificados expansor = new ExpansorCertificados();
        ClienteHttp clienteHttp = ClienteHttp.comTransportePadrao();
        ServicoDownload servico = new ServicoDownload(clienteHttp, expansor, stagingWriter, config);

        // Baixa PRO e HOM para a staging; falhas sao preservadas e registradas no manifest
        // pelo proprio servico (Req 1.4, 7.1). Nenhuma operacao toca o keystore (Req 1.2, 2.2).
        ResultadoDownloadStaging resultado = servico.executar();
        Manifest manifest = resultado.manifest();

        // Emite o Relatorio_Inconsistencias ANTES de qualquer persistencia (Req 3.1).
        out.println(RelatorioInconsistenciasBuilder.construir(manifest));

        // Reporta a contagem de certificados gravados na staging (Req 1.3).
        int gravados = resultado.certificadosGravados();
        int falhas = resultado.numeroFalhas();
        out.println("Certificados gravados na staging: " + gravados
                + " (diretorio: " + staging + ")");

        // Monta o ResultadoExecucao a partir das falhas e traduz em exit code (Req 9.1, 9.2).
        String mensagem = falhas > 0
                ? falhas + " fonte(s) de download falharam; consulte o Relatorio_Inconsistencias"
                : "download concluido; " + gravados + " certificado(s) gravado(s) na staging";
        ResultadoExecucao execucao = new ResultadoExecucao(PROCESSO, falhas, mensagem);

        out.println(DecisorExitCode.mensagemFinal(execucao));
        return DecisorExitCode.codigo(execucao);
    }
}
