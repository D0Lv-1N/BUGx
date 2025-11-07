package ui

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// MenuSelection represents the user's chosen scan modes.
type MenuSelection struct {
	Modes []int
	Exit  bool
}

// ClearScreen best-effort terminal clear for a cleaner UI.
func ClearScreen() {
	// ANSI clear: works on most terminals; if not supported, harmless.
	fmt.Print("\033[2J\033[H")
}

// PrintHeader renders the main header for BUGx.
func PrintHeader() {
	fmt.Println("==================================================")
	fmt.Println("                    BUGx MENU                     ")
	fmt.Println("==================================================")
}

// PrintMainMenu renders the mode selection menu.
func PrintMainMenu() {
	PrintHeader()
	fmt.Println("Pilih mode scan (bisa lebih dari satu, pisahkan dengan koma):")
	fmt.Println()
	fmt.Println(" 1. XSS")
	fmt.Println(" 2. SQLi")
	fmt.Println(" 3. LFI / RFI")
	fmt.Println(" 4. SSRF")
	fmt.Println(" 5. Open Redirect")
	fmt.Println(" 6. Sensitive Files / Backup")
	fmt.Println(" 7. CMS / Panel")
	fmt.Println(" 8. RCE / High Impact")
	fmt.Println(" 9. RUN ALL")
	fmt.Println(" 0. Keluar")
	fmt.Println()
	fmt.Print("Input mode (contoh: 1,2,3): ")
}

// ReadModes reads and parses the user's selection for scan modes.
func ReadModes() MenuSelection {
	line := readLine()
	line = strings.TrimSpace(line)

	if line == "" {
		return MenuSelection{Modes: nil, Exit: false}
	}

	// Single "0" → exit langsung
	if line == "0" {
		return MenuSelection{Modes: nil, Exit: true}
	}

	parts := strings.Split(line, ",")
	seen := make(map[int]struct{})
	var modes []int

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		if n == 0 {
			// Jika ada 0 di kombinasi, interpretasi sebagai keluar
			return MenuSelection{Modes: nil, Exit: true}
		}
		if n < 0 || n > 9 {
			continue
		}
		if _, ok := seen[n]; !ok {
			seen[n] = struct{}{}
			modes = append(modes, n)
		}
	}

	return MenuSelection{Modes: modes, Exit: false}
}

// PrintSetupTarget prints the target/speed setup screen.
func PrintSetupTarget() {
	ClearScreen()
	PrintHeader()
	fmt.Println("Setup Target")
	fmt.Println("--------------------------------------------------")
	fmt.Println("Masukan target dan kecepatan scan.")
	fmt.Println("Contoh target: https://example.com")
	fmt.Println("Kecepatan mempengaruhi flags tools eksternal (threads/conc).")
	fmt.Println("--------------------------------------------------")
}

// ReadTarget prompts and reads the target URL.
func ReadTarget() string {
	fmt.Print("Masukan target url (http(s)://example.com): ")
	raw := strings.TrimSpace(readLine())
	return raw
}

// ReadSpeed prompts and reads the concurrency/speed (with default).
func ReadSpeed(defaultSpeed int) int {
	fmt.Printf("Masukan kecepatan (default %d): ", defaultSpeed)
	raw := strings.TrimSpace(readLine())
	if raw == "" {
		return defaultSpeed
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultSpeed
	}
	return n
}

// PrintRunHeader shows the processing screen header.
func PrintRunHeader(target string, speed int, modes []int) {
	ClearScreen()
	PrintHeader()
	fmt.Println("Proses scanning dimulai")
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Target  : %s\n", target)
	fmt.Printf("Speed   : %d\n", speed)
	fmt.Printf("Mode(s) : %v\n", modes)
	fmt.Println("--------------------------------------------------")
	fmt.Println("Output di bawah adalah output asli dari tools eksternal.")
	fmt.Println()
}

// PrintSummary renders a simple summary box after scans.
func PrintSummary(target string, modes []int, toolsUsed []string) {
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("                    RINGKASAN                     ")
	fmt.Println("==================================================")
	fmt.Printf("Target      : %s\n", target)
	fmt.Printf("Mode(s)     : %v\n", modes)
	if len(toolsUsed) > 0 {
		fmt.Printf("Tools Used  : %s\n", strings.Join(toolsUsed, ", "))
	} else {
		fmt.Println("Tools Used  : (tidak terdeteksi / tidak dicatat)")
	}
	fmt.Println("==================================================")
	fmt.Print("Tekan ENTER untuk kembali ke menu utama...")
	_ = readLine()
}

// readLine reads a single line from stdin (trimmed).
func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
