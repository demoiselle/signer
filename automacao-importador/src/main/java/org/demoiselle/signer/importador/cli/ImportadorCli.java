package org.demoiselle.signer.importador.cli;

import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

/**
 * Comando raiz picocli da aplicacao autonoma {@code automacao-importador}.
 *
 * <p>Agrega os dois processos independentes como subcomandos do mesmo binario:</p>
 * <ul>
 *   <li>{@link ComandoBaixar} ({@code baixar}) &mdash; baixa as cadeias para a Staging
 *       e emite o Relatorio_Inconsistencias, sem tocar no keystore;</li>
 *   <li>{@link ComandoPersistir} ({@code persistir}) &mdash; le a Staging e grava os
 *       certificados no keystore BKS, com deduplicacao configuravel.</li>
 * </ul>
 *
 * <p>Reconhece {@code -h}/{@code --help} global via
 * {@code mixinStandardHelpOptions = true} (Req 1.1). Quando invocado <em>sem</em>
 * subcomando, imprime a ajuda (usage) e retorna um codigo diferente de zero,
 * sinalizando que nenhum processo foi executado.</p>
 *
 * <p>Requisitos atendidos: 1.1, 9.1, 9.2.</p>
 */
@Command(
        name = "automacao-importador",
        description = {
                "Ferramenta autonoma para baixar e persistir cadeias de certificados "
                        + "ICP-Brasil (producao e homologacao) no keystore BKS de destino, "
                        + "manipulado nativamente via BouncyCastle (sem keytool/openssl).",
                "",
                "Use um dos subcomandos:",
                "  baixar     Baixa as cadeias para a Staging e emite o Relatorio_Inconsistencias.",
                "  persistir  Le a Staging e grava os certificados no keystore, com deduplicacao."
        },
        subcommands = {
                ComandoBaixar.class,
                ComandoPersistir.class
        },
        mixinStandardHelpOptions = true,
        synopsisSubcommandLabel = "COMANDO"
)
public class ImportadorCli implements Callable<Integer> {

    @Spec
    CommandSpec spec;

    /**
     * Invocado quando nenhum subcomando e fornecido: imprime a ajuda (usage) e
     * retorna um codigo diferente de zero, deixando claro que nenhum processo
     * ({@code baixar}/{@code persistir}) foi executado.
     *
     * @return {@link CommandLine#USAGE} (codigo != 0)
     */
    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }
}
