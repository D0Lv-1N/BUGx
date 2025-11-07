package runner

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

// Mode identifiers for menu selection.
const (
	ModeXSS       = 1
	ModeSQLi      = 2
	ModeLFI       = 3
	ModeSSRF      = 4
	ModeRedirect  = 5
	ModeSensitive = 6
	ModeCMS       = 7
	ModeRCE       = 8
)

// RunModes runs all selected modes sequentially for the given target and speed.
// - Modes are expected to be normalized & sorted by the caller.
// - Returns unique list of tool names that were actually invoked (for summary).
func RunModes(modes []int, target string, speed int) []string {
	used := make(map[string]struct{})

	for _, m := range modes {
		switch m {
		case ModeXSS:
			for _, t := range runXSSChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeSQLi:
			for _, t := range runSQLiChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeLFI:
			for _, t := range runLFIChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeSSRF:
			for _, t := range runSSRFChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeRedirect:
			for _, t := range runRedirectChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeSensitive:
			for _, t := range runSensitiveChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeCMS:
			for _, t := range runCMSChain(target, speed) {
				used[t] = struct{}{}
			}
		case ModeRCE:
			// RCE / High impact chains: nuclei critical/rce/takeover templates, etc.
			for _, t := range runRCEChain(target, speed) {
				used[t] = struct{}{}
			}
		default:
			fmt.Printf("[INFO] Mode %d belum diimplementasikan.\n", m)
		}
	}

	var tools []string
	for t := range used {
		tools = append(tools, t)
	}
	return tools
}

//
// XSS MODE (1)
//

// runXSSChain:
// - Fokus pada parameterized URLs untuk XSS
// - Chain (adaptif, tergantung tools tersedia):
//  1. subfinder -d domain -o subs.txt
//  2. httpx -l subs.txt -mc 200 -o hosts.txt
//  3. cat hosts.txt | gau --threads speed | gf xss > gf_xss.txt
//  4. httpx -l gf_xss.txt -mc 200 -o clean_xss.txt
//  5. nuclei -l clean_xss.txt --severity medium,high,critical -tags xss -o results/xss/.../nuclei.json
//  6. dalfox file clean_xss.txt --skip-mining-all -w speed -o results/xss/.../dalfox.json
func runXSSChain(target string, speed int) []string {
	fmt.Println("========== [MODE XSS] ==========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[XSS] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE XSS] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "xss")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("xss", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")
	gfXss := filepath.Join(tmpDir, "gf_xss.txt")
	clean := filepath.Join(tmpDir, "clean_xss.txt")

	var used []string

	// 1) subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("XSS", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("XSS", "subfinder", err)
		}
	} else {
		logMissing("XSS", "subfinder")
	}

	// 2) httpx (subs -> hosts)
	if hasTool("httpx") && fileExists(subs) {
		args := []string{
			"-l", subs,
			"-o", hosts,
			"-mc", "200",
		}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("XSS", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("XSS", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("XSS", "httpx")
	}

	// 3) gau (hosts -> gau_xss)
	if hasTool("gau") && fileExists(hosts) {
		gauOut := filepath.Join(tmpDir, "gau_xss.txt")
		line := fmt.Sprintf("cat %s | gau --threads %d --verbose > %s",
			escapeShell(hosts),
			maxInt(speed, 1),
			escapeShell(gauOut),
		)
		logShell("XSS", line)
		if err := runShellLive(line); err == nil {
			used = append(used, "gau")
		} else {
			logFail("XSS", "gau xss", err)
		}
		// 4) gf xss (gau_xss -> gf_xss)
		if hasTool("gf") && fileExists(gauOut) {
			lineGF := fmt.Sprintf("cat %s | gf xss > %s",
				escapeShell(gauOut),
				escapeShell(gfXss),
			)
			logShell("XSS", lineGF)
			if err := runShellLive(lineGF); err == nil {
				used = append(used, "gf")
			} else {
				logFail("XSS", "gf xss", err)
			}
		} else if !hasTool("gf") {
			logMissing("XSS", "gf")
		}
	} else {
		if !fileExists(hosts) {
			logInfo("XSS", "hosts.txt tidak ada, lewati gau+gf xss")
		}
		if !hasTool("gau") {
			logMissing("XSS", "gau")
		}
		if !hasTool("gf") {
			logMissing("XSS", "gf")
		}
	}

	// 4) httpx filter lagi (gf_xss -> clean) setelah gf menghasilkan kandidat
	if hasTool("httpx") && fileExists(gfXss) {
		args := []string{
			"-l", gfXss,
			"-o", clean,
			"-mc", "200",
		}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("XSS", "httpx (gf_xss->clean)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("XSS", "httpx gf_xss", err)
		}
	}

	// Target list untuk vuln scan
	// nuclei diarahkan ke hasil gau (gau_xss) atau hosts sebagai fallback,
	// bukan ke hasil gf_xss agar cakupan tetap luas.
	gauXss := filepath.Join(tmpDir, "gau_xss.txt")
	list := chooseFirstExisting(gauXss, hosts)
	if list == "" {
		logInfo("XSS", "Tidak ada daftar URL kandidat, hentikan mode XSS.")
		fmt.Println("========== [/MODE XSS] =========")
		return unique(used)
	}

	// 5) nuclei
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{
			"-l", list,
			"--severity", "medium,high,critical",
			"-tags", "xss",
			"-o", out,
		}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("XSS", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("XSS", "nuclei", err)
		}
	} else {
		logMissing("XSS", "nuclei")
	}

	// 6) dalfox
	if hasTool("dalfox") {
		out := filepath.Join(resultsDir, "dalfox.json")
		args := []string{
			"file", list,
			"--skip-mining-all",
			"--custom-payload", filepath.Join(buildBugxBaseDir(), "wordlist", "xss.txt"),
			"-w", fmt.Sprintf("%d", maxInt(speed, 1)),
			"-o", out,
		}
		logStep("XSS", "dalfox", args)
		if err := runCommandLive("dalfox", args...); err == nil {
			used = append(used, "dalfox")
		} else {
			logFail("XSS", "dalfox", err)
		}
	} else {
		logMissing("XSS", "dalfox")
	}

	fmt.Println("========== [/MODE XSS] =========")
	return unique(used)
}

//
// SQLi MODE (2)
//

func runSQLiChain(target string, speed int) []string {
	fmt.Println("========== [MODE SQLi] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[SQLi] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE SQLi] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "sqli")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("sqli", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")
	gfSQLi := filepath.Join(tmpDir, "gf_sqli.txt")
	clean := filepath.Join(tmpDir, "clean_sqli.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SQLi", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("SQLi", "subfinder", err)
		}
	} else {
		logMissing("SQLi", "subfinder")
	}

	// httpx (subs -> hosts)
	if hasTool("httpx") && fileExists(subs) {
		args := []string{"-l", subs, "-o", hosts, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SQLi", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("SQLi", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("SQLi", "httpx")
	}

	// gau (hosts -> gau_sqli)
	if hasTool("gau") && fileExists(hosts) {
		gauOut := filepath.Join(tmpDir, "gau_sqli.txt")
		line := fmt.Sprintf("cat %s | gau --threads %d --verbose > %s",
			escapeShell(hosts),
			maxInt(speed, 1),
			escapeShell(gauOut),
		)
		logShell("SQLi", line)
		if err := runShellLive(line); err == nil {
			used = append(used, "gau")
		} else {
			logFail("SQLi", "gau sqli", err)
		}
		// gf sqli (gau_sqli -> gf_sqli)
		if hasTool("gf") && fileExists(gauOut) {
			lineGF := fmt.Sprintf("cat %s | gf sqli > %s",
				escapeShell(gauOut),
				escapeShell(gfSQLi),
			)
			logShell("SQLi", lineGF)
			if err := runShellLive(lineGF); err == nil {
				used = append(used, "gf")
			} else {
				logFail("SQLi", "gf sqli", err)
			}
		} else if !hasTool("gf") {
			logMissing("SQLi", "gf")
		}
	} else {
		if !fileExists(hosts) {
			logInfo("SQLi", "hosts.txt tidak ada, lewati gau+gf sqli")
		}
		if !hasTool("gau") {
			logMissing("SQLi", "gau")
		}
		if !hasTool("gf") {
			logMissing("SQLi", "gf")
		}
	}

	// httpx filter lagi
	if hasTool("httpx") && fileExists(gfSQLi) {
		args := []string{"-l", gfSQLi, "-o", clean, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SQLi", "httpx (gf_sqli->clean)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("SQLi", "httpx gf_sqli", err)
		}
	}

	// nuclei diarahkan ke hasil gau (gau_sqli) atau hosts sebagai fallback.
	gauSQLi := filepath.Join(tmpDir, "gau_sqli.txt")
	list := chooseFirstExisting(gauSQLi, hosts)
	if list == "" {
		logInfo("SQLi", "Tidak ada URL kandidat, hentikan mode SQLi.")
		fmt.Println("========== [/MODE SQLi] =========")
		return unique(used)
	}

	// nuclei -tags sqli
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{"-l", list, "-tags", "sqli", "-o", out}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("SQLi", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("SQLi", "nuclei", err)
		}
	} else {
		logMissing("SQLi", "nuclei")
	}

	// Untuk sqlmap: kita hanya siapkan input list; tidak auto-exploit agresif.
	// (Bisa ditambahkan sebagai opsi manual di masa depan.)

	fmt.Println("========== [/MODE SQLi] =========")
	return unique(used)
}

//
// LFI/RFI MODE (3)
//

func runLFIChain(target string, speed int) []string {
	fmt.Println("========== [MODE LFI/RFI] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[LFI] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE LFI/RFI] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "lfi")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("lfi", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")
	gfLfi := filepath.Join(tmpDir, "gf_lfi.txt")
	clean := filepath.Join(tmpDir, "clean_lfi.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("LFI", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("LFI", "subfinder", err)
		}
	} else {
		logMissing("LFI", "subfinder")
	}

	// httpx
	if hasTool("httpx") && fileExists(subs) {
		args := []string{"-l", subs, "-o", hosts, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("LFI", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("LFI", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("LFI", "httpx")
	}

	// gau (hosts -> gau_lfi)
	if hasTool("gau") && fileExists(hosts) {
		gauOut := filepath.Join(tmpDir, "gau_lfi.txt")
		line := fmt.Sprintf("cat %s | gau --threads %d --verbose > %s",
			escapeShell(hosts),
			maxInt(speed, 1),
			escapeShell(gauOut),
		)
		logShell("LFI", line)
		if err := runShellLive(line); err == nil {
			used = append(used, "gau")
		} else {
			logFail("LFI", "gau lfi", err)
		}
		// gf lfi (gau_lfi -> gf_lfi)
		if hasTool("gf") && fileExists(gauOut) {
			lineGF := fmt.Sprintf("cat %s | gf lfi > %s",
				escapeShell(gauOut),
				escapeShell(gfLfi),
			)
			logShell("LFI", lineGF)
			if err := runShellLive(lineGF); err == nil {
				used = append(used, "gf")
			} else {
				logFail("LFI", "gf lfi", err)
			}
		} else if !hasTool("gf") {
			logMissing("LFI", "gf")
		}
	}

	// httpx filter lagi
	if hasTool("httpx") && fileExists(gfLfi) {
		args := []string{"-l", gfLfi, "-o", clean, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("LFI", "httpx (gf_lfi->clean)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("LFI", "httpx gf_lfi", err)
		}
	}

	// nuclei diarahkan ke hasil gau (gau_lfi) atau hosts sebagai fallback.
	gauLfi := filepath.Join(tmpDir, "gau_lfi.txt")
	list := chooseFirstExisting(gauLfi, hosts)
	if list == "" {
		logInfo("LFI", "Tidak ada URL kandidat LFI.")
		fmt.Println("========== [/MODE LFI/RFI] =========")
		return unique(used)
	}

	// nuclei -tags lfi
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{"-l", list, "-tags", "lfi", "-o", out}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("LFI", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("LFI", "nuclei", err)
		}
	} else {
		logMissing("LFI", "nuclei")
	}

	fmt.Println("========== [/MODE LFI/RFI] =========")
	return unique(used)
}

//
// SSRF MODE (4)
//

func runSSRFChain(target string, speed int) []string {
	fmt.Println("========== [MODE SSRF] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[SSRF] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE SSRF] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "ssrf")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("ssrf", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")
	gfSSRF := filepath.Join(tmpDir, "gf_ssrf.txt")
	clean := filepath.Join(tmpDir, "clean_ssrf.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SSRF", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("SSRF", "subfinder", err)
		}
	} else {
		logMissing("SSRF", "subfinder")
	}

	// httpx
	if hasTool("httpx") && fileExists(subs) {
		args := []string{"-l", subs, "-o", hosts, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SSRF", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("SSRF", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("SSRF", "httpx")
	}

	// gau (hosts -> gau_ssrf)
	if hasTool("gau") && fileExists(hosts) {
		gauOut := filepath.Join(tmpDir, "gau_ssrf.txt")
		line := fmt.Sprintf("cat %s | gau --threads %d --verbose > %s",
			escapeShell(hosts),
			maxInt(speed, 1),
			escapeShell(gauOut),
		)
		logShell("SSRF", line)
		if err := runShellLive(line); err == nil {
			used = append(used, "gau")
		} else {
			logFail("SSRF", "gau ssrf", err)
		}
		// gf ssrf (gau_ssrf -> gf_ssrf)
		if hasTool("gf") && fileExists(gauOut) {
			lineGF := fmt.Sprintf("cat %s | gf ssrf > %s",
				escapeShell(gauOut),
				escapeShell(gfSSRF),
			)
			logShell("SSRF", lineGF)
			if err := runShellLive(lineGF); err == nil {
				used = append(used, "gf")
			} else {
				logFail("SSRF", "gf ssrf", err)
			}
		} else if !hasTool("gf") {
			logMissing("SSRF", "gf")
		}
	}

	// httpx filter lagi
	if hasTool("httpx") && fileExists(gfSSRF) {
		args := []string{"-l", gfSSRF, "-o", clean, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SSRF", "httpx (gf_ssrf->clean)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("SSRF", "httpx gf_ssrf", err)
		}
	}

	// nuclei diarahkan ke hasil gau (gau_ssrf) atau hosts sebagai fallback.
	gauSSRF := filepath.Join(tmpDir, "gau_ssrf.txt")
	list := chooseFirstExisting(gauSSRF, hosts)
	if list == "" {
		logInfo("SSRF", "Tidak ada URL kandidat SSRF.")
		fmt.Println("========== [/MODE SSRF] =========")
		return unique(used)
	}

	// nuclei -tags ssrf
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{"-l", list, "-tags", "ssrf", "-o", out}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("SSRF", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("SSRF", "nuclei", err)
		}
	} else {
		logMissing("SSRF", "nuclei")
	}

	fmt.Println("========== [/MODE SSRF] =========")
	return unique(used)
}

//
// OPEN REDIRECT MODE (5)
//

func runRedirectChain(target string, speed int) []string {
	fmt.Println("========== [MODE OPEN REDIRECT] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[REDIRECT] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE OPEN REDIRECT] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "redirect")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("redirect", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")
	gfRedir := filepath.Join(tmpDir, "gf_redirect.txt")
	clean := filepath.Join(tmpDir, "clean_redirect.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("REDIRECT", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("REDIRECT", "subfinder", err)
		}
	} else {
		logMissing("REDIRECT", "subfinder")
	}

	// httpx
	if hasTool("httpx") && fileExists(subs) {
		args := []string{"-l", subs, "-o", hosts, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("REDIRECT", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("REDIRECT", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("REDIRECT", "httpx")
	}

	// gau (hosts -> gau_redirect)
	if hasTool("gau") && fileExists(hosts) {
		gauOut := filepath.Join(tmpDir, "gau_redirect.txt")
		line := fmt.Sprintf("cat %s | gau --threads %d --verbose > %s",
			escapeShell(hosts),
			maxInt(speed, 1),
			escapeShell(gauOut),
		)
		logShell("REDIRECT", line)
		if err := runShellLive(line); err == nil {
			used = append(used, "gau")
		} else {
			logFail("REDIRECT", "gau redirect", err)
		}
		// gf redirect (gau_redirect -> gf_redirect)
		if hasTool("gf") && fileExists(gauOut) {
			lineGF := fmt.Sprintf("cat %s | gf redirect > %s",
				escapeShell(gauOut),
				escapeShell(gfRedir),
			)
			logShell("REDIRECT", lineGF)
			if err := runShellLive(lineGF); err == nil {
				used = append(used, "gf")
			} else {
				logFail("REDIRECT", "gf redirect", err)
			}
		} else if !hasTool("gf") {
			logMissing("REDIRECT", "gf")
		}
	}

	// httpx filter lagi
	if hasTool("httpx") && fileExists(gfRedir) {
		args := []string{"-l", gfRedir, "-o", clean, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("REDIRECT", "httpx (gf_redirect->clean)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("REDIRECT", "httpx gf_redirect", err)
		}
	}

	// nuclei diarahkan ke hasil gau (gau_redirect) atau hosts sebagai fallback.
	gauRedirect := filepath.Join(tmpDir, "gau_redirect.txt")
	list := chooseFirstExisting(gauRedirect, hosts)
	if list == "" {
		logInfo("REDIRECT", "Tidak ada URL kandidat redirect.")
		fmt.Println("========== [/MODE OPEN REDIRECT] =========")
		return unique(used)
	}

	// nuclei -tags redirect
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{"-l", list, "-tags", "redirect", "-o", out}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("REDIRECT", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("REDIRECT", "nuclei", err)
		}
	} else {
		logMissing("REDIRECT", "nuclei")
	}

	fmt.Println("========== [/MODE OPEN REDIRECT] =========")
	return unique(used)
}

//
// SENSITIVE / BACKUP MODE (6)
//

func runSensitiveChain(target string, speed int) []string {
	fmt.Println("========== [MODE SENSITIVE/BACKUP] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[SENSITIVE] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE SENSITIVE/BACKUP] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "sensitive")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("sensitive", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SENSITIVE", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("SENSITIVE", "subfinder", err)
		}
	} else {
		logMissing("SENSITIVE", "subfinder")
	}

	// httpx (subs -> hosts)
	if hasTool("httpx") && fileExists(subs) {
		args := []string{"-l", subs, "-o", hosts, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("SENSITIVE", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("SENSITIVE", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("SENSITIVE", "httpx")
	}

	// Di mode ini kita tidak memaksakan wordlist tertentu.
	// User bebas pakai ffuf/dirsearch/gobuster/feroxbuster manual.
	// BUG-X cukup melakukan nuclei exposures/files/backup bila tersedia list host.

	list := chooseFirstExisting(hosts, subs)
	if list == "" {
		logInfo("SENSITIVE", "Tidak ada host list untuk scanning exposures.")
		fmt.Println("========== [/MODE SENSITIVE/BACKUP] =========")
		return unique(used)
	}

	// nuclei exposures/files/backup
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{
			"-l", list,
			"-tags", "exposure,exposures,files,backup",
			"-o", out,
		}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("SENSITIVE", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("SENSITIVE", "nuclei", err)
		}
	} else {
		logMissing("SENSITIVE", "nuclei")
	}

	fmt.Println("========== [/MODE SENSITIVE/BACKUP] =========")
	return unique(used)
}

//
// CMS / PANEL MODE (7)
//

func runCMSChain(target string, speed int) []string {
	fmt.Println("========== [MODE CMS/PANEL] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[CMS] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE CMS/PANEL] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "cms")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("cms", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("CMS", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("CMS", "subfinder", err)
		}
	} else {
		logMissing("CMS", "subfinder")
	}

	// httpx
	if hasTool("httpx") && fileExists(subs) {
		args := []string{
			"-l", subs,
			"-o", hosts,
			"-mc", "200",
			"-td", // technology detect
		}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("CMS", "httpx (subs->hosts tech-detect)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("CMS", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("CMS", "httpx")
	}

	list := chooseFirstExisting(hosts, subs)
	if list == "" {
		logInfo("CMS", "Tidak ada host list untuk scanning CMS.")
		fmt.Println("========== [/MODE CMS/PANEL] =========")
		return unique(used)
	}

	// nuclei CMS tags
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{
			"-l", list,
			"-tags", "wp,wordpress,drupal,joomla,cms,login,panel",
			"-o", out,
		}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("CMS", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("CMS", "nuclei", err)
		}
	} else {
		logMissing("CMS", "nuclei")
	}

	// wpscan, whatweb, dll tetap dianggap manual; tidak dipaksa otomatis di sini.

	fmt.Println("========== [/MODE CMS/PANEL] =========")
	return unique(used)
}

//
// RCE / HIGH IMPACT MODE (8)
//

func runRCEChain(target string, speed int) []string {
	fmt.Println("========== [MODE RCE/HIGH IMPACT] =========")
	domain := extractDomain(target)
	if domain == "" {
		fmt.Printf("[RCE] Target tidak valid: %s\n", target)
		fmt.Println("========== [/MODE RCE/HIGH IMPACT] =========")
		return nil
	}

	tmpDir := buildTempDir(domain, "rce")
	defer cleanupTempDir(tmpDir)

	resultsDir := buildModeResultsDir("rce", domain)
	_ = os.MkdirAll(resultsDir, 0o755)

	subs := filepath.Join(tmpDir, "subs.txt")
	hosts := filepath.Join(tmpDir, "hosts.txt")

	var used []string

	// subfinder
	if hasTool("subfinder") {
		args := []string{"-d", domain, "-o", subs}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("RCE", "subfinder", args)
		if err := runCommandLive("subfinder", args...); err == nil {
			used = append(used, "subfinder")
		} else {
			logFail("RCE", "subfinder", err)
		}
	} else {
		logMissing("RCE", "subfinder")
	}

	// httpx
	if hasTool("httpx") && fileExists(subs) {
		args := []string{"-l", subs, "-o", hosts, "-mc", "200"}
		if speed > 0 {
			args = append(args, "-t", fmt.Sprintf("%d", speed))
		}
		logStep("RCE", "httpx (subs->hosts)", args)
		if err := runCommandLive("httpx", args...); err == nil {
			used = append(used, "httpx")
		} else {
			logFail("RCE", "httpx", err)
		}
	} else if !hasTool("httpx") {
		logMissing("RCE", "httpx")
	}

	list := chooseFirstExisting(hosts, subs)
	if list == "" {
		logInfo("RCE", "Tidak ada host list untuk scanning high-impact.")
		fmt.Println("========== [/MODE RCE/HIGH IMPACT] =========")
		return unique(used)
	}

	// nuclei -tags rce,critical,takeover,ssrf high
	if hasTool("nuclei") {
		out := filepath.Join(resultsDir, "nuclei.json")
		args := []string{
			"-l", list,
			"-tags", "rce,critical,takeover",
			"-o", out,
		}
		if speed > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", speed))
		}
		logStep("RCE", "nuclei", args)
		if err := runCommandLive("nuclei", args...); err == nil {
			used = append(used, "nuclei")
		} else {
			logFail("RCE", "nuclei", err)
		}
	} else {
		logMissing("RCE", "nuclei")
	}

	fmt.Println("========== [/MODE RCE/HIGH IMPACT] =========")
	return unique(used)
}

//
// Shared helpers
//

// hasTool checks if a binary is available in PATH.
func hasTool(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runCommandLive executes a command and streams stdout/stderr live.
func runCommandLive(name string, args ...string) error {
	fmt.Printf("[CMD] %s %s\n", name, strings.Join(args, " "))
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runShellLive runs a shell command (for simple pipe chains) with live output.
func runShellLive(line string) error {
	fmt.Printf("[SHELL] %s\n", line)
	cmd := exec.Command("sh", "-c", line)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// fileExists checks if a regular file exists.
func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// chooseFirstExisting returns the first non-empty path that exists.
func chooseFirstExisting(paths ...string) string {
	for _, p := range paths {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

// buildTempDir constructs a temp directory path for a specific mode.
func buildTempDir(domain, mode string) string {
	safeDomain := sanitizeForPath(domain)
	if mode == "" {
		mode = "run"
	}
	ts := time.Now().UnixNano()
	return filepath.Join(os.TempDir(), fmt.Sprintf("BUGx-%s-%s-%d", mode, safeDomain, ts))
}

// cleanupTempDir removes a temp directory and its contents.
func cleanupTempDir(dir string) {
	if dir == "" {
		return
	}
	_ = os.RemoveAll(dir)
}

// buildModeResultsDir -> ~/BUGx/results/<mode>/<domain>
func buildModeResultsDir(mode, domain string) string {
	if mode == "" {
		mode = "misc"
	}
	domain = sanitizeForPath(domain)

	base := ""
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		base = u.HomeDir
	} else {
		base = os.Getenv("HOME")
	}
	if base == "" {
		// Fallback ke relative jika HOME tidak ada
		base = "."
	}
	return filepath.Join(base, "BUGx", "results", strings.ToLower(mode), domain)
}

// extractDomain tries to normalize URL or host to bare domain.
func extractDomain(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return stripPortAndPath(raw)
	}
	parts := strings.SplitN(raw, "://", 2)
	if len(parts) != 2 {
		return ""
	}
	return stripPortAndPath(parts[1])
}

func stripPortAndPath(s string) string {
	if i := strings.Index(s, "/"); i != -1 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i != -1 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// sanitizeForPath ensures safe directory/file name.
func sanitizeForPath(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "target"
	}
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(s)
}

// escapeShell wraps string for safe use in sh -c.
func escapeShell(s string) string {
	if s == "" {
		return "''"
	}
	escaped := strings.ReplaceAll(s, `'`, `'\''`)
	return "'" + escaped + "'"
}

// maxInt returns max(a,b).
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// unique returns a deduplicated copy of tools slice.
func unique(list []string) []string {
	if len(list) == 0 {
		return list
	}
	seen := make(map[string]struct{}, len(list))
	var out []string
	for _, v := range list {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// Logging helpers to keep output clean & expressive.

func logStep(mode, tool string, args []string) {
	fmt.Printf("[%s] %s -> %s %s\n", mode, "RUN", tool, strings.Join(args, " "))
}

func logShell(mode, line string) {
	fmt.Printf("[%s] SHELL -> %s\n", mode, line)
}

func logFail(mode, tool string, err error) {
	fmt.Printf("[%s] [FAIL] %s: %v\n", mode, tool, err)
}

func logMissing(mode, tool string) {
	fmt.Printf("[%s] [WARN] Tool '%s' tidak ditemukan. Step terkait dilewati.\n", mode, tool)
}

func logInfo(mode, msg string) {
	fmt.Printf("[%s] [INFO] %s\n", mode, msg)
}

// buildBugxBaseDir returns base directory for BUGx data (~/BUGx by default).
func buildBugxBaseDir() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, "BUGx")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, "BUGx")
	}
	return "BUGx"
}
