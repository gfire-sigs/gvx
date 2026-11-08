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

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.util.Base64;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Starts one executable of the native library directory and reports its
 * output and exit code.
 *
 * <p>Arguments of {@code am instrument}: {@code exe} names the library file,
 * such as {@code librungv.so}. {@code args64} holds the arguments, separated
 * by NUL bytes and encoded in base64. The working directory is the files
 * directory of the app. Each output line goes to the status stream, and the
 * file {@code last-run.log} of the files directory keeps the whole output.
 */
public final class Run extends Instrumentation {
    private Bundle arguments;

    @Override
    public void onCreate(Bundle arguments) {
        this.arguments = arguments;
        start();
    }

    @Override
    public void onStart() {
        Context ctx = getTargetContext();
        File files = ctx.getFilesDir();
        List<String> cmd = new ArrayList<>();
        cmd.add(ctx.getApplicationInfo().nativeLibraryDir + "/"
                + arguments.getString("exe", "libandroidprobe.so"));
        String args64 = arguments.getString("args64", "");
        if (!args64.isEmpty()) {
            String joined = new String(Base64.decode(args64, Base64.DEFAULT), StandardCharsets.UTF_8);
            for (String a : joined.split("\0")) {
                cmd.add(a.replace("@FILES@", files.getPath()));
            }
        }
        int code;
        StringBuilder tail = new StringBuilder();
        try (FileWriter log = new FileWriter(new File(files, "last-run.log"))) {
            ProcessBuilder pb = new ProcessBuilder(cmd).directory(files).redirectErrorStream(true);
            Map<String, String> env = pb.environment();
            env.put("HOME", files.getPath());
            env.put("TMPDIR", ctx.getCacheDir().getPath());
            env.put("XDG_CACHE_HOME", ctx.getCacheDir().getPath());
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    log.write(line + "\n");
                    log.flush();
                    Bundle status = new Bundle();
                    status.putString(Instrumentation.REPORT_KEY_STREAMRESULT, line + "\n");
                    sendStatus(1, status);
                    tail.append(line).append('\n');
                    if (tail.length() > 16384) {
                        tail.delete(0, tail.length() - 16384);
                    }
                }
            }
            code = p.waitFor();
        } catch (Exception e) {
            tail.append("probe app: ").append(e).append('\n');
            code = 127;
        }
        Bundle result = new Bundle();
        result.putString(Instrumentation.REPORT_KEY_STREAMRESULT, "exit code " + code + "\n");
        result.putInt("exit", code);
        finish(code == 0 ? 0 : 1, result);
    }
}
