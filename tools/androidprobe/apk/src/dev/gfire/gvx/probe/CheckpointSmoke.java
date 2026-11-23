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

package dev.gfire.gvx.probe;

import android.content.Context;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import dev.gfire.gvx.Gvx;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final class CheckpointSmoke {
    private static final long TIMEOUT_SECONDS = 45;

    private CheckpointSmoke() {}

    static void run(Context ctx, String guest) throws Exception {
        int port;
        try (ServerSocket portReservation = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = portReservation.getLocalPort();
        }
        String endpoint = "-control-socket=tcp://127.0.0.1:" + port;
        File token = new File(ctx.getCacheDir(), "gvx/control/tcp-" + port + ".token");
        File bundle = Files.createTempDirectory(ctx.getFilesDir().toPath(), "checkpoint-").toFile();
        ExecutorService pipes = Executors.newFixedThreadPool(2);
        Process server = null;
        Process client = null;
        try {
            server = Gvx.start(ctx, List.of("run", "-platform=systrap", "-net=none", "-bin=" + guest,
                    endpoint, "-checkpoint-dir=" + bundle));
            Future<String> serverErr = read(pipes, server.getErrorStream());
            BufferedReader guestOut = new BufferedReader(
                    new InputStreamReader(server.getInputStream(), StandardCharsets.UTF_8));
            Future<String> readiness = pipes.submit(guestOut::readLine);
            String ready = readiness.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!"READY:memory".equals(ready)) {
                throw new IOException("guest not ready: " + ready + "\n"
                        + serverErr.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            }
            StructStat st = Os.stat(token.getPath());
            if (!OsConstants.S_ISREG(st.st_mode) || st.st_uid != android.os.Process.myUid()
                    || (st.st_mode & 0777) != 0600 || st.st_size != 65) {
                throw new IOException("app cache does not contain a private token");
            }
            client = Gvx.start(ctx, List.of("checkpoint", endpoint, "-leave-running"));
            client.getOutputStream().close();
            Future<String> clientErr = read(pipes, client.getErrorStream());
            if (!client.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IOException("checkpoint client timed out");
            }
            if (client.exitValue() != 0 || new File(bundle, "manifest.json").length() == 0) {
                throw new IOException("checkpoint client exit " + client.exitValue() + ": "
                        + clientErr.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            }
            server.getOutputStream().write("resume\n".getBytes(StandardCharsets.UTF_8));
            server.getOutputStream().close();
            if (!server.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IOException("checkpoint server did not resume");
            }
            if (server.exitValue() != 0) {
                throw new IOException("checkpoint server exit " + server.exitValue() + ": "
                        + serverErr.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            }
        } finally {
            stop(client);
            stop(server);
            pipes.shutdownNow();
            Files.deleteIfExists(token.toPath());
            try (Stream<Path> files = Files.walk(bundle.toPath())) {
                for (Path path : files.sorted(Comparator.reverseOrder()).collect(Collectors.toList())) {
                    Files.delete(path);
                }
            }
        }
    }

    private static Future<String> read(ExecutorService pipes, InputStream stream) {
        return pipes.submit(() -> {
            try (stream) {
                return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            }
        });
    }

    private static void stop(Process process) throws InterruptedException {
        if (process != null && process.isAlive()) {
            process.destroyForcibly();
            process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
    }
}
