package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"automacao-importador/pkg/cadeias"
	"automacao-importador/pkg/politicas"
)

func main() {
	env := flag.String("env", "", "Ambiente para atualizar: 'pro' ou 'hom'")
	updateLpa := flag.Bool("update-lpa", false, "Lê o LPA.xml da ICP-Brasil e adiciona novas políticas no politicas.txt")
	help := flag.Bool("help", false, "Exibe esta mensagem de ajuda")
	flag.Parse()

	if *help || (*env == "" && !*updateLpa) || (*env != "" && *env != "pro" && *env != "hom") {
		mostrarAjuda()
		os.Exit(1)
	}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Erro ao obter diretório: %v", err)
	}

	politicasFile := filepath.Join(wd, "../policy-engine/automacao-atualizacao/politicas.txt")

	if *updateLpa {
		fmt.Println("================================================================")
		fmt.Println("Atualizando Lista de Políticas (LPA)")
		fmt.Println("================================================================")
		if err := politicas.AtualizarListaLPA(politicasFile); err != nil {
			log.Fatalf("Falha ao atualizar LPA: %v", err)
		}
		
		// Se não foi passado um ambiente para baixar logo em seguida, sai.
		if *env == "" {
			fmt.Println("================================================================")
			os.Exit(0)
		}
	}

	var cadConfig cadeias.Config
	var polConfig politicas.Config

	if *env == "pro" {
		cadConfig = cadeias.Config{
			Env:              "pro",
			ZipURL:           "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip",
			TargetKeystore:   filepath.Join(wd, "../chain-icp-brasil/src/main/resources/cadeiasicpbrasil.bks"),
			KeystorePass:     "serprosigner",
			BouncyCastlePath: filepath.Join(wd, "../chain-icp-brasil/src/scripts_keytool/bcprov-lts8on-2.73.11.jar"),
		}
		polConfig = politicas.Config{
			Env:           "pro",
			PoliticasFile: politicasFile,
			TargetDir:     filepath.Join(wd, "../policy-engine/src/main/resources/org/demoiselle/signer/policy/engine/artifacts"),
		}
	} else if *env == "hom" {
		cadConfig = cadeias.Config{
			Env:              "hom",
			HomologURL:       "https://repositoriohom.serpro.gov.br/cadeias/",
			TargetKeystore:   filepath.Join(wd, "../chain-icp-brasil-homolog/src/main/resources/cadeiasicpbrasil-HOMOLOGACAO.bks"),
			KeystorePass:     "serprosigner",
			BouncyCastlePath: filepath.Join(wd, "../chain-icp-brasil-homolog/bcprov-lts8on-2.73.11.jar"),
		}
		polConfig = politicas.Config{
			Env: "hom",
		}
	}

	fmt.Println("================================================================")
	fmt.Printf("Iniciando Atualização de Artefatos (%s)\n", strings.ToUpper(*env))
	fmt.Println("================================================================")

	err = politicas.AtualizarPoliticas(polConfig)
	if err != nil {
		log.Printf("Erro em políticas: %v", err)
	}

	err = cadeias.AtualizarCadeias(cadConfig)
	if err != nil {
		log.Printf("Erro em cadeias: %v", err)
	}

	fmt.Println("================================================================")
	fmt.Println("ATUALIZAÇÃO CONCLUÍDA!")
	fmt.Println("================================================================")
}

func mostrarAjuda() {
	fmt.Println("================================================================")
	fmt.Println("  Importador e Atualizador de Artefatos (ICP-Brasil)")
	fmt.Println("================================================================")
	fmt.Println("Uso: go run main.go [flags]")
	fmt.Println("\nFlags disponíveis:")
	fmt.Println("  -env pro      Atualiza cadeias e políticas de PRODUÇÃO.")
	fmt.Println("  -env hom      Atualiza apenas as cadeias de HOMOLOGAÇÃO.")
	fmt.Println("  -update-lpa   Consulta a LPA.xml oficial e adiciona novas políticas no politicas.txt.")
	fmt.Println("  -help         Exibe esta mensagem.")
	fmt.Println("\nExemplos de uso:")
	fmt.Println("  cd automacao-importador")
	fmt.Println("  go run main.go -update-lpa          (Apenas atualiza o TXT com novas políticas)")
	fmt.Println("  go run main.go -env=pro -update-lpa (Descobre políticas novas e já baixa tudo de PRO)")
	fmt.Println("================================================================")
}
