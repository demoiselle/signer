package politicas

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// AtualizarListaLPA acessa o XML oficial da ICP-Brasil, extrai as políticas e insere as novas no politicas.txt
func AtualizarListaLPA(politicasFile string) error {
	lpaURL := "http://politicas.icpbrasil.gov.br/LPA.xml"
	log.Printf("[LPA] Verificando novas políticas na LPA oficial: %s", lpaURL)

	client := &http.Client{}
	req, err := http.NewRequest("GET", lpaURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("erro ao conectar na LPA: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("erro HTTP %d ao acessar LPA", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bodyStr := string(bodyBytes)

	// Regex para extrair tudo dentro de <PolicyURI>...</PolicyURI> (ignorando possíveis namespaces)
	re := regexp.MustCompile(`(?i)<(?:[a-zA-Z0-9_-]+:)?PolicyURI[^>]*>(.*?)</(?:[a-zA-Z0-9_-]+:)?PolicyURI>`)
	matches := re.FindAllStringSubmatch(bodyStr, -1)

	// Lemos o que já existe no politicas.txt para não duplicar
	existing := make(map[string]bool)
	f, err := os.Open(politicasFile)
	if err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				existing[line] = true
			}
		}
		f.Close()
	} else {
		log.Printf("[LPA] Arquivo %s não encontrado, será criado um novo.", politicasFile)
	}

	var novas []string
	for _, match := range matches {
		if len(match) > 1 {
			url := strings.TrimSpace(match[1])
			
			// Ignora a raiz do repositório
			if url == "http://politicas.icpbrasil.gov.br" || url == "http://politicas.icpbrasil.gov.br/" {
				continue
			}

			// Adiciona a política original (geralmente .xml)
			if !existing[url] {
				novas = append(novas, url)
				existing[url] = true
			}

			// No ecossistema ICP-Brasil, para cada .xml existe um .der equivalente.
			// O script garante que ambas as extensões sejam baixadas.
			if strings.HasSuffix(url, ".xml") {
				derUrl := strings.TrimSuffix(url, ".xml") + ".der"
				if !existing[derUrl] {
					novas = append(novas, derUrl)
					existing[derUrl] = true
				}
			}
		}
	}

	if len(novas) > 0 {
		log.Printf("[LPA] Foram encontradas %d novas URLs de políticas não cadastradas.", len(novas))
		
		fOut, err := os.OpenFile(politicasFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("erro ao abrir %s para escrita: %v", politicasFile, err)
		}
		defer fOut.Close()

		fOut.WriteString("\n\n# --- Adicionadas automaticamente via -update-lpa ---")
		for _, u := range novas {
			fOut.WriteString("\n" + u)
		}
		log.Printf("[LPA] Arquivo politicas.txt atualizado com sucesso!")
	} else {
		log.Printf("[LPA] Nenhuma política nova encontrada. O politicas.txt já está 100%% atualizado.")
	}

	return nil
}
