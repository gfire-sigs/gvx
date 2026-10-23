// Research tool. It measures how reliably a byte scan finds syscall
// instructions in x86-64 and arm64 Linux binaries. Run it in a directory that
// holds x64/ and a64/ root filesystem trees, for example the Alpine minirootfs
// archives.
package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/arch/x86/x86asm"
)

type stat struct {
	files                                                   int
	textBytes, dataBytes                                    uint64
	pairs, real, inside, unstable, dataPairs                uint64
	armTextWords, armSVC, armSVC0, armDataWords, armDataSVC uint64
}

// sweepLabels decodes data linearly from start and labels every byte offset:
// 1 = first byte of a SYSCALL instruction, 2 = first byte of another
// instruction, 3 = inside an instruction, 0 = not decoded.
func sweepLabels(data []byte, start int) []byte {
	lab := make([]byte, len(data))
	for a := start; a < len(data); {
		inst, err := x86asm.Decode(data[a:], 64)
		if err != nil || inst.Len == 0 {
			a++
			continue
		}
		if inst.Op == x86asm.SYSCALL {
			lab[a] = 1
		} else {
			lab[a] = 2
		}
		for k := 1; k < inst.Len && a+k < len(data); k++ {
			lab[a+k] = 3
		}
		a += inst.Len
	}
	return lab
}

// scanX86 finds every 0F 05 byte pair in executable sections. It labels each
// pair with 16 linear sweeps that start at different byte offsets. A pair
// counts as stable when all 16 sweeps give the same label.
func scanX86(f *elf.File, st *stat) {
	for _, s := range f.Sections {
		if s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		if s.Flags&elf.SHF_EXECINSTR == 0 {
			st.dataBytes += uint64(len(data))
			for i := 0; i+1 < len(data); i++ {
				if data[i] == 0x0f && data[i+1] == 0x05 {
					st.dataPairs++
				}
			}
			continue
		}
		st.textBytes += uint64(len(data))
		var labs [][]byte
		for k := 0; k < 16; k++ {
			labs = append(labs, sweepLabels(data, k))
		}
		for i := 0; i+1 < len(data); i++ {
			if data[i] != 0x0f || data[i+1] != 0x05 {
				continue
			}
			st.pairs++
			same := true
			for k := 1; k < 16; k++ {
				if labs[k][i] != labs[0][i] {
					same = false
					break
				}
			}
			switch {
			case !same:
				st.unstable++
			case labs[0][i] == 1:
				st.real++
			case labs[0][i] == 3:
				st.inside++
			}
		}
	}
}

// scanArm counts the 32-bit words that look like SVC in executable and in
// non-executable sections. Every aligned word in an executable section is an
// instruction boundary, so no sweep is needed.
func scanArm(f *elf.File, st *stat) {
	for _, s := range f.Sections {
		if s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_ALLOC == 0 {
			continue
		}
		data, err := s.Data()
		if err != nil {
			continue
		}
		for i := 0; i+4 <= len(data); i += 4 {
			w := binary.LittleEndian.Uint32(data[i:])
			isSVC := w&0xFFE0001F == 0xD4000001
			if s.Flags&elf.SHF_EXECINSTR != 0 {
				st.armTextWords++
				if isSVC {
					st.armSVC++
					if w == 0xD4000001 {
						st.armSVC0++
					}
				}
			} else {
				st.armDataWords++
				if isSVC {
					st.armDataSVC++
				}
			}
		}
	}
}

func walk(root string, machine elf.Machine, fn func(*elf.File)) {
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		f, err := elf.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		if f.Machine == machine {
			fn(f)
		}
		return nil
	})
}

func main() {
	var x, a stat
	walk("x64", elf.EM_X86_64, func(f *elf.File) {
		x.files++
		scanX86(f, &x)
	})
	walk("a64", elf.EM_AARCH64, func(f *elf.File) {
		a.files++
		scanArm(f, &a)
	})
	mb := func(b uint64) float64 { return float64(b) / (1 << 20) }
	fmt.Printf("x86-64: files=%d text=%.2f MB data=%.2f MB\n", x.files, mb(x.textBytes), mb(x.dataBytes))
	fmt.Printf("  0F 05 byte pairs in text: %d (%.1f per MB)\n", x.pairs, float64(x.pairs)/mb(x.textBytes))
	fmt.Printf("  labeled the same by 16 sweeps: %d real SYSCALL instructions, %d inside another instruction, %d labeled differently\n", x.real, x.inside, x.unstable)
	fmt.Printf("  0F 05 byte pairs in non-executable data: %d (%.1f per MB)\n", x.dataPairs, float64(x.dataPairs)/mb(x.dataBytes))
	fmt.Printf("arm64: files=%d text=%.2f MB data=%.2f MB\n", a.files, mb(a.armTextWords*4), mb(a.armDataWords*4))
	fmt.Printf("  SVC words in text: %d (svc #0: %d)\n", a.armSVC, a.armSVC0)
	fmt.Printf("  non-executable data words that match the SVC pattern: %d (%.3f per MB)\n", a.armDataSVC, float64(a.armDataSVC)/mb(a.armDataWords*4))
}
