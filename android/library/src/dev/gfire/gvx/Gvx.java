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

package dev.gfire.gvx;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Starts {@code rungv} from the native library directory of the app.
 *
 * <p>The package installer writes the native library directory, and the app
 * cannot change it, so the start resolves no path that the app can write
 * (GVXIP-006 section 2.5). The Sentry runs in that child process with its host
 * lockdown. The caller reads the standard streams and the exit code from the
 * returned {@link Process}.
 *
 * <p>Android has no {@code /etc/resolv.conf}. For the commands that can pull an
 * image, {@link #start} passes the DNS servers of the active network with
 * {@code --host-dns}.
 */
public final class Gvx {
    /** The file name of rungv in the native library directory. */
    public static final String EXECUTABLE = "librungv.so";

    /** The commands of rungv that resolve registry names. */
    private static final Set<String> PULLING_COMMANDS =
            new HashSet<>(Arrays.asList("run", "pull"));

    private Gvx() {}

    /**
     * Starts rungv with args, such as {@code ["run", "alpine:3", "uname", "-a"]}.
     *
     * <p>The child has {@code HOME} in the files directory of the app and the
     * OCI cache and temporary files in its cache directory.
     */
    public static Process start(Context ctx, List<String> args) throws IOException {
        if (args.isEmpty()) {
            throw new IllegalArgumentException("rungv needs a command");
        }
        List<String> cmd = new ArrayList<>();
        cmd.add(new File(ctx.getApplicationInfo().nativeLibraryDir, EXECUTABLE).getPath());
        cmd.add(args.get(0));
        if (PULLING_COMMANDS.contains(args.get(0))) {
            for (String server : activeDnsServers(ctx)) {
                cmd.add("--host-dns");
                cmd.add(server);
            }
        }
        cmd.addAll(args.subList(1, args.size()));
        ProcessBuilder pb = new ProcessBuilder(cmd).directory(ctx.getFilesDir());
        Map<String, String> env = pb.environment();
        env.put("HOME", ctx.getFilesDir().getPath());
        env.put("XDG_CACHE_HOME", ctx.getCacheDir().getPath());
        env.put("TMPDIR", ctx.getCacheDir().getPath());
        return pb.start();
    }

    /** Returns the DNS servers of the active network, or an empty list. */
    public static List<String> activeDnsServers(Context ctx) {
        ConnectivityManager cm = ctx.getSystemService(ConnectivityManager.class);
        if (cm == null) {
            return Collections.emptyList();
        }
        Network network = cm.getActiveNetwork();
        LinkProperties props = network == null ? null : cm.getLinkProperties(network);
        if (props == null) {
            return Collections.emptyList();
        }
        List<String> servers = new ArrayList<>();
        for (InetAddress addr : props.getDnsServers()) {
            // A link-local address needs a zone, which --host-dns does not take.
            if (!addr.isLinkLocalAddress()) {
                servers.add(addr.getHostAddress());
            }
        }
        return servers;
    }
}
