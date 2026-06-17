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
	help := flag.Bool("help", false, "Exibe esta mensagem de ajuda")
	flag.Parse()

	if *help || *env == "" || (*env != "pro" && *env != "hom") {
		mostrarAjuda()
		os.Exit(1)
	}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Erro ao obter diretório: %v", err)
	}

	var cadConfig cadeias.Config
	var polConfig politicas.Config

	if *env == "pro" {
		cadConfig = cadeias.Config{
			Env:              "pro",
			ZipURL:           "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip",
			TargetKeystore:   filepath.Join(wd, "chain-icp-brasil/src/main/resources/cadeiasicpbrasil.bks"),
			KeystorePass:     "serprosigner",
			BouncyCastlePath: filepath.Join(wd, "chain-icp-brasil/src/scripts_keytool/bcprov-jdk18on-1.80.jar"),
		}
		polConfig = politicas.Config{
			Env:           "pro",
			PoliticasFile: filepath.Join(wd, "policy-engine/automacao-atualizacao/politicas.txt"),
			TargetDir:     filepath.Join(wd, "policy-engine/src/main/resources/org/demoiselle/signer/policy/engine/artifacts"),
		}
	} else if *env == "hom" {
		cadConfig = cadeias.Config{
			Env:              "hom",
			HomologURL:       "https://repositoriohom.serpro.gov.br/cadeias/",
			TargetKeystore:   filepath.Join(wd, "chain-icp-brasil-homolog/src/main/resources/cadeiasicpbrasil-HOMOLOGACAO.bks"),
			KeystorePass:     "serprosigner",
			BouncyCastlePath: filepath.Join(wd, "chain-icp-brasil-homolog/bcprov-jdk18on-1.80.jar"),
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
	fmt.Println("Uso: go run main.go -env=<ambiente>")
	fmt.Println("\nParâmetros obrigatórios:")
	fmt.Println("  -env pro    Atualiza cadeias e políticas de PRODUÇÃO.")
	fmt.Println("              (Baixa do ITI e gera cadeiasicpbrasil.bks)")
	fmt.Println("  -env hom    Atualiza apenas as cadeias de HOMOLOGAÇÃO.")
	fmt.Println("              (Baixa do Repositório Serpro e gera BKS)")
	fmt.Println("\nOutros:")
	fmt.Println("  -help       Exibe esta mensagem.")
	fmt.Println("\nExemplos de uso:")
	fmt.Println("  cd automacao-importador")
	fmt.Println("  go run main.go -env=pro")
	fmt.Println("  go run main.go -env=hom")
	fmt.Println("================================================================")
}
