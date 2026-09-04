package main

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type MavenMetadata struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Versioning struct {
		LastUpdated string `xml:"lastUpdated"`
		Snapshot    struct {
			Timestamp   string `xml:"timestamp"`
			BuildNumber int    `xml:"buildNumber"`
		} `xml:"snapshot"`
		SnapshotVersions []struct {
			Classifier string `xml:"classifier"`
			Extension  string `xml:"extension"`
			Value      string `xml:"value"`
			Updated    string `xml:"updated"`
		} `xml:"snapshotVersions>snapshotVersion"`
	} `xml:"versioning"`
	Version string `xml:"version"`
}

var modules = []ModuleDef{
	{dir: "bom", artifact: "bom"},
	{dir: "parent", artifact: "parent"},
	{dir: "core", artifact: "signer-core"},
	{dir: "cryptography", artifact: "signer-cryptography"},
	{dir: "chain-icp-brasil", artifact: "chain-icp-brasil"},
	{dir: "chain-icp-brasil-homolog", artifact: "chain-icp-brasil-homolog"},
	{dir: "chain-iti", artifact: "chain-iti"},
	{dir: "chain-iti-homolog", artifact: "chain-iti-homolog"},
	{dir: "chain-serpro-neosigner", artifact: "chain-serpro-neosigner"},
	{dir: "policy-engine", artifact: "policy-engine"},
	{dir: "policy-impl-cades", artifact: "policy-impl-cades"},
	{dir: "policy-impl-pades", artifact: "policy-impl-pades"},
	{dir: "policy-impl-xades", artifact: "policy-impl-xades"},
	{dir: "signer-xmldsig", artifact: "signer-xmldsig"},
	{dir: "timestamp", artifact: "signer-timestamp"},
}

type ModuleDef struct {
	dir      string
	artifact string
}

type ModuleReport struct {
	Module    ModuleDef
	Exists    bool
	Version   string
	BuildTs   string
	BuildNum  int
	Files     []FileCheck
	Error     string
}

type FileCheck struct {
	Name   string
	Status string // ok, missing, error
}

const (
	snapshotsBase = "https://central.sonatype.com/repository/maven-snapshots"
	centralBase   = "https://repo1.maven.org/maven2"
)

func runCommand(cmd *exec.Cmd) error {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func setupJavaEnv() {
	if os.Getenv("JAVA_HOME") == "" {
		javaBin, err := exec.LookPath("java")
		if err != nil {
			return
		}
		resolved, err := filepath.EvalSymlinks(javaBin)
		if err != nil {
			resolved = javaBin
		}
		javaHome := filepath.Dir(filepath.Dir(resolved))
		os.Setenv("JAVA_HOME", javaHome)
	}
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		os.Setenv("PATH", filepath.Join(javaHome, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
}

func readVersion(wd string) string {
	data, err := os.ReadFile(filepath.Join(wd, "pom.xml"))
	if err != nil {
		return ""
	}
	s := string(data)
	marker := "<version>"
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	s = s[i+len(marker):]
	j := strings.Index(s, "</version>")
	if j < 0 {
		return ""
	}
	v := strings.TrimSpace(s[:j])
	if v == "4.6.2-SNAPSHOT" {
		return "4.6.2"
	}
	v = strings.TrimSuffix(v, "-SNAPSHOT")
	return v
}

func checkFile(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Sprintf("erro: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return "ok"
	}
	return fmt.Sprintf("HTTP %d", resp.StatusCode)
}

func verifyModule(artifact, version string, isRelease bool) ModuleReport {
	r := ModuleReport{Module: ModuleDef{artifact: artifact}}

	if isRelease {
		r = checkRelease(artifact, version)
	} else {
		r = checkSnapshot(artifact, version)
	}
	return r
}

func checkSnapshot(artifact, version string) ModuleReport {
	r := ModuleReport{}
	r.Module = ModuleDef{artifact: artifact}

	metaURL := fmt.Sprintf("%s/org/demoiselle/signer/%s/%s-SNAPSHOT/maven-metadata.xml", snapshotsBase, artifact, version)
	resp, err := http.Get(metaURL)
	if err != nil {
		r.Error = fmt.Sprintf("erro ao acessar repositório: %v", err)
		return r
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		r.Error = fmt.Sprintf("HTTP %d ao acessar metadados", resp.StatusCode)
		return r
	}

	var meta MavenMetadata
	if err := xml.NewDecoder(resp.Body).Decode(&meta); err != nil {
		r.Error = fmt.Sprintf("erro ao decodificar XML: %v", err)
		return r
	}

	if len(meta.Versioning.SnapshotVersions) == 0 {
		r.Error = "nenhuma versão snapshot encontrada"
		return r
	}

	r.Exists = true
	r.Version = meta.Version
	r.BuildTs = meta.Versioning.Snapshot.Timestamp
	r.BuildNum = meta.Versioning.Snapshot.BuildNumber

	for _, sv := range meta.Versioning.SnapshotVersions {
		ext := sv.Extension
		display := ext
		if sv.Classifier != "" {
			display = sv.Classifier + "." + ext
		}

		fullName := artifact + "-" + sv.Value
		if sv.Classifier != "" {
			fullName += "-" + sv.Classifier
		}
		fullName += "." + ext

		fileURL := fmt.Sprintf("%s/org/demoiselle/signer/%s/%s-SNAPSHOT/%s", snapshotsBase, artifact, version, fullName)
		status := checkFile(fileURL)
		r.Files = append(r.Files, FileCheck{Name: display, Status: status})
	}

	return r
}

func checkRelease(artifact, version string) ModuleReport {
	r := ModuleReport{}
	r.Module = ModuleDef{artifact: artifact}

	baseURL := fmt.Sprintf("%s/org/demoiselle/signer/%s/%s", centralBase, artifact, version)

	suffixes := []struct {
		path string
		name string
	}{
		{fmt.Sprintf("/%s-%s.pom", artifact, version), "pom"},
		{fmt.Sprintf("/%s-%s.jar", artifact, version), "jar"},
		{fmt.Sprintf("/%s-%s-sources.jar", artifact, version), "sources.jar"},
		{fmt.Sprintf("/%s-%s.pom.asc", artifact, version), "pom.asc"},
		{fmt.Sprintf("/%s-%s.jar.asc", artifact, version), "jar.asc"},
		{fmt.Sprintf("/%s-%s-sources.jar.asc", artifact, version), "sources.jar.asc"},
	}

	allOk := true
	for _, sf := range suffixes {
		fileURL := baseURL + sf.path
		status := checkFile(fileURL)
		if status != "ok" {
			allOk = false
		}
		r.Files = append(r.Files, FileCheck{Name: sf.name, Status: status})
	}

	r.Exists = allOk
	r.Version = version
	if allOk {
		r.BuildTs = "release"
	}

	return r
}

func printReport(reports []ModuleReport, isRelease bool) {
	total := len(reports)
	passed := 0
	failed := 0

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("  📋 RELATÓRIO DE PUBLICAÇÃO")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Repositório: %s\n", map[bool]string{false: "SNAPSHOTs (central.sonatype.com)", true: "Maven Central (repo1.maven.org)"}[isRelease])
	fmt.Println(strings.Repeat("=", 60))

	for _, r := range reports {
		status := "✅"
		if !r.Exists || r.Error != "" {
			status = "❌"
			failed++
		} else {
			passed++
		}

		fmt.Printf("\n%s %s\n", status, r.Module.artifact)
		fmt.Printf("   └─ Grupo:    org.demoiselle.signer\n")

		if r.Error != "" {
			fmt.Printf("   └─ Erro:     %s\n", r.Error)
			continue
		}

		fmt.Printf("   └─ Versão:   %s\n", r.Version)
		if r.BuildTs != "" {
			fmt.Printf("   └─ Build:    %s", r.BuildTs)
			if r.BuildNum > 0 {
				fmt.Printf(" (#%d)", r.BuildNum)
			}
			fmt.Println()
		}

		fmt.Println("   └─ Arquivos:")
		for _, f := range r.Files {
			icon := "✅"
			if f.Status != "ok" {
				icon = "❌"
			}
			fmt.Printf("      %s %s", icon, f.Name)
			if f.Status != "ok" {
				fmt.Printf(" (%s)", f.Status)
			}
			fmt.Println()
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  RESUMO: %d/%d módulos publicados\n", passed, total)
	fmt.Println(strings.Repeat("=", 60))

	if failed > 0 {
		fmt.Printf("\n  Módulos com falha:\n")
		for _, r := range reports {
			if !r.Exists || r.Error != "" {
				fmt.Printf("    ❌ %s", r.Module.artifact)
				if r.Error != "" {
					fmt.Printf(" — %s", r.Error)
				}
				fmt.Println()
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

func main() {
	start := time.Now()

	setupJavaEnv()

	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("❌ Erro ao obter diretório atual: %v\n", err)
		os.Exit(1)
	}

	_, err = os.Stat(filepath.Join(wd, "pom.xml"))
	if err != nil {
		fmt.Printf("❌ Execute o publicador da raiz do projeto (onde está o pom.xml principal)\n")
		os.Exit(1)
	}

	isRelease := false
	validar := false
	snapshot := false

	for _, arg := range os.Args[1:] {
		switch arg {
		case "-release", "--release":
			isRelease = true
		case "-snapshot", "--snapshot":
			snapshot = true
		case "-validar", "--validar":
			validar = true
		}
	}

	if !snapshot && !isRelease && !validar {
		fmt.Println("Uso: go run publicador.go [flag]")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  -snapshot            Publica SNAPSHOT no Sonatype")
		fmt.Println("  -release             Publica RELEASE no Maven Central")
		fmt.Println("  -validar             Valida a publicação no repositório")
		fmt.Println()
		fmt.Println("Exemplos:")
		fmt.Println("  go run publicador.go -snapshot")
		fmt.Println("  go run publicador.go -release")
		fmt.Println("  go run publicador.go -validar")
		os.Exit(0)
	}

	if validar {
		version := readVersion(wd)
		if version == "" {
			fmt.Printf("❌ Não foi possível ler a versão do pom.xml raiz\n")
			os.Exit(1)
		}

		fmt.Printf("🔍 Verificando publicação da versão %s", version)
		if isRelease {
			fmt.Printf(" (Maven Central)")
		} else {
			fmt.Printf(" (SNAPSHOT)")
		}
		fmt.Println()

		var reports []ModuleReport

		for _, mod := range modules {
			modPath := filepath.Join(wd, mod.dir)
			if _, err := os.Stat(modPath); os.IsNotExist(err) {
				continue
			}
			pomPath := filepath.Join(modPath, "pom.xml")
			if _, err := os.Stat(pomPath); os.IsNotExist(err) {
				continue
			}

			fmt.Printf("\n📦 Verificando %s...\n", mod.artifact)
			r := verifyModule(mod.artifact, version, isRelease)
			reports = append(reports, r)
		}

		printReport(reports, isRelease)
		duration := time.Since(start)
		fmt.Printf("\n⏱️  Verificação concluída em %v\n", duration.Truncate(time.Second))
		return
	}

	mode := "SNAPSHOT"
	if isRelease {
		mode = "RELEASE"
	}

	fmt.Printf("🚀 Publicando Demoiselle Signer (%s)\n", mode)
	fmt.Println(strings.Repeat("-", 50))

	args := []string{"clean", "deploy", "-Dmaven.test.skip=true", "-Dmaven.javadoc.skip=true", "-B",
		"-Dmaven.wagon.http.retryHandler.count=5",
		"-Dmaven.wagon.http.connectionTimeout=600000",
		"-Dmaven.wagon.http.readTimeout=600000",
		"-Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn",
	}

	if isRelease {
		args = append(args, "-P", "release")
	}

	maxRetries := 20
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			fmt.Printf("\n🔄 Tentativa %d de %d...\n", retry+1, maxRetries)
			time.Sleep(15 * time.Second)
		}

		cmd := exec.Command("mvn", args...)
		cmd.Dir = wd
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err == nil {
			lastErr = nil
			break
		}
		lastErr = err
		fmt.Printf("⚠️  Falha na tentativa %d: %v\n", retry+1, err)
	}

	if lastErr != nil {
		fmt.Printf("\n❌ Publicação falhou após %d tentativas\n", maxRetries)
		os.Exit(1)
	}

	if !isRelease {
		fmt.Println("\n🔍 Validando publicação no repositório de SNAPSHOTs...")
		time.Sleep(5 * time.Second)

		version := readVersion(wd)
		allOk := true
		var reports []ModuleReport

		for _, mod := range modules {
			modPath := filepath.Join(wd, mod.dir)
			if _, err := os.Stat(modPath); os.IsNotExist(err) {
				continue
			}
			pomPath := filepath.Join(modPath, "pom.xml")
			if _, err := os.Stat(pomPath); os.IsNotExist(err) {
				continue
			}

			fmt.Printf("\n📦 Verificando %s...\n", mod.artifact)
			r := verifyModule(mod.artifact, version, false)
			reports = append(reports, r)
			if !r.Exists || r.Error != "" {
				fmt.Printf("   ⚠️  %s não encontrado no repositório\n", mod.artifact)
				allOk = false
			} else {
				fmt.Printf("   ✅ %s publicado com sucesso!\n", mod.artifact)
			}
		}

		printReport(reports, false)

		if !allOk {
			fmt.Println("\n⚠️  Alguns módulos podem não ter sido publicados.")
		}
	}

	duration := time.Since(start)
	fmt.Println("\n" + strings.Repeat("-", 50))
	fmt.Printf("🏁 Publicação %s finalizada em %v\n", mode, duration.Truncate(time.Second))
}
