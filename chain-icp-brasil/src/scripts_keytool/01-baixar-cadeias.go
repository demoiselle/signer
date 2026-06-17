package main

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	downloadURL = "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactadox.zip"
	zipFile     = "cadeias.zip"
	targetDir   = "novascadeias"
)

func main() {
	fmt.Printf("Iniciando download das cadeias de: %s\n", downloadURL)

	// Limpa diretório de destino
	os.RemoveAll(targetDir)
	os.MkdirAll(targetDir, 0755)

	// Download do ZIP
	err := downloadFile(downloadURL, zipFile)
	if err != nil {
		fmt.Printf("[ERRO] Falha no download: %v\n", err)
		return
	}
	fmt.Println("[OK] Download concluído.")

	// Unzip
	err = unzip(zipFile, targetDir)
	if err != nil {
		fmt.Printf("[ERRO] Falha ao extrair: %v\n", err)
		return
	}
	fmt.Printf("[OK] Arquivos extraídos para: %s\n", targetDir)

	// Remove o zip após extração
	os.Remove(zipFile)
}

func downloadFile(url, path string) error {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	// Adiciona User-Agent de navegador para evitar bloqueios
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code erro: %d", resp.StatusCode)
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Ignora diretórios e arquivos que não são .crt ou .cer
		if f.FileInfo().IsDir() {
			continue
		}

		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".crt") && !strings.HasSuffix(lowerName, ".cer") {
			continue
		}

		// Garante que o nome do arquivo seja limpo (sem caminhos maliciosos)
		fpath := filepath.Join(dest, filepath.Base(f.Name))

		err = extractFile(f, fpath)
		if err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}
