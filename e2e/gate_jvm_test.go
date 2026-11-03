// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build darwin || windows || linux

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// jvmProgram makes HotSpot compile a hot loop with C2, run eight threads that
// share a map and allocate, collect garbage, and run a parallel stream. The
// source launcher compiles the file in the guest first, so javac runs too.
const jvmProgram = `import java.util.concurrent.*;
import java.util.stream.*;

public class Hello {
    static long primes(int n) {
        long count = 0;
        outer:
        for (int i = 2; i < n; i++) {
            for (int j = 2; (long) j * j <= i; j++) {
                if (i % j == 0) continue outer;
            }
            count++;
        }
        return count;
    }

    public static void main(String[] args) throws Exception {
        System.out.println("primes=" + primes(300000));
        ExecutorService pool = Executors.newFixedThreadPool(8);
        ConcurrentHashMap<Integer, Integer> map = new ConcurrentHashMap<>();
        Future<?>[] fs = new Future<?>[8];
        for (int t = 0; t < 8; t++) {
            final int base = t * 100000;
            fs[t] = pool.submit(() -> {
                for (int i = 0; i < 100000; i++) {
                    map.merge((base + i) % 5000, 1, Integer::sum);
                    if (i % 10000 == 0) {
                        byte[] junk = new byte[1 << 20];
                        junk[i % junk.length] = 1;
                    }
                }
            });
        }
        for (Future<?> f : fs) f.get();
        pool.shutdown();
        System.gc();
        long total = map.values().stream().mapToLong(Integer::longValue).sum();
        System.out.println("map=" + map.size() + " total=" + total);
        System.out.println("stream=" + IntStream.range(0, 1000).parallel().map(x -> x * x).sum());
    }
}
`

// jvmScript runs the program twice: with the default safepoint protocol, and
// with -XX:+UseSystemMemoryBarrier, which makes HotSpot serialize its threads
// with membarrier(MEMBARRIER_CMD_PRIVATE_EXPEDITED).
const jvmScript = `set -e
cd /workspace
java -version 2>&1
echo "== default"
java Hello.java
echo "== membarrier"
java -XX:+UnlockExperimentalVMOptions -XX:+UseSystemMemoryBarrier -Xlog:os=info Hello.java 2>&1
`

// TestE2EGateJVM runs the Temurin 21 JDK on every backend. HotSpot uses
// signals, guard pages, JIT code that it patches, safepoints, and membarrier,
// so the gate covers engine paths that Node does not reach.
func TestE2EGateJVM(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "Hello.java"), []byte(jvmProgram), 0o644); err != nil {
				t.Fatal(err)
			}
			out := mustRunGuest(t, guestSpec{
				plat:      b.plat,
				image:     "eclipse-temurin:21-jdk-alpine",
				argv:      []string{"sh", "-c", jvmScript},
				workspace: dir,
				timeout:   20 * time.Minute,
			})
			requireContains(t, "java output", out,
				`openjdk version "21.`,
				"== default\nprimes=25997\nmap=5000 total=800000\nstream=332833500\n",
				"Using MEMBARRIER PRIVATE_EXPEDITED",
			)
			if got := strings.Count(out, "primes=25997\n"); got != 2 {
				t.Errorf("program results = %d, want 2; full text:\n%s", got, out)
			}
		})
	}
}
