package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/D0Lv-1N/BUGx/internal/runner"
	"github.com/D0Lv-1N/BUGx/internal/ui"
)

// main adalah entrypoint utama BUG-X.
// Tugas:
// - Menampilkan menu interaktif.
// - Mengizinkan multi-select mode (1,2,3,...).
// - Menjamin urutan eksekusi:
//   - Input "1,3,2" -> tetap dieksekusi sebagai 1 -> 2 -> 3.
//   - Mode RUN ALL (9) -> eksekusi 1..8 berurutan.
//
// - Mengoper target & speed ke lapisan runner.
// - Menampilkan ringkasan + tools yang dipakai.
func main() {
	const defaultSpeed = 50

	for {
		ui.ClearScreen()
		ui.PrintMainMenu()

		selection := ui.ReadModes()
		if selection.Exit {
			return
		}

		modes := normalizeAndOrderModes(selection.Modes)
		if len(modes) == 0 {
			fmt.Println("[INFO] Tidak ada mode valid yang dipilih. Tekan ENTER untuk kembali ke menu...")
			ui.PrintSummary("", nil, nil)
			continue
		}

		// Setup target & speed
		ui.PrintSetupTarget()
		targetRaw := strings.TrimSpace(ui.ReadTarget())
		target := normalizeTarget(targetRaw)
		if target == "" {
			fmt.Println("[WARN] Target tidak boleh kosong. Tekan ENTER untuk kembali ke menu...")
			ui.PrintSummary("", nil, nil)
			continue
		}

		speed := ui.ReadSpeed(defaultSpeed)
		if speed <= 0 {
			speed = defaultSpeed
		}

		ui.PrintRunHeader(target, speed, modes)

		// Eksekusi semua mode secara berurutan (sama behavior dengan RUN ALL)
		toolsUsed := runner.RunModes(modes, target, speed)

		// Ringkasan + tunggu ENTER
		ui.PrintSummary(target, modes, toolsUsed)
	}
}

// normalizeAndOrderModes:
// - Hapus duplikat.
// - Jika ada 9 (RUN ALL) -> jadikan [1..8] (urut).
// - Kalau multi input tanpa 9: urutkan ascending (1..8).
// - Hanya izinkan 1..9, lainnya dibuang.
func normalizeAndOrderModes(input []int) []int {
	if len(input) == 0 {
		return nil
	}

	seen := make(map[int]struct{})
	hasRunAll := false

	for _, m := range input {
		if m == 9 {
			hasRunAll = true
			continue
		}
		if m >= 1 && m <= 8 {
			seen[m] = struct{}{}
		}
	}

	var result []int
	if hasRunAll {
		// RUN ALL = 1..8 berurutan
		for m := 1; m <= 8; m++ {
			result = append(result, m)
		}
		return result
	}

	for m := range seen {
		result = append(result, m)
	}
	sort.Ints(result)

	return result
}

// normalizeTarget:
// - trim spasi
// - jika kosong -> ""
// - jika tidak ada skema -> prepend https://
// - jika sudah ada skema http/https -> pakai apa adanya
func normalizeTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}

	return "https://" + raw
}
