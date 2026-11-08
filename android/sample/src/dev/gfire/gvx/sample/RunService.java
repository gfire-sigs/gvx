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

package dev.gfire.gvx.sample;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.util.Log;
import dev.gfire.gvx.Gvx;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

/**
 * Runs one rungv command in a foreground service.
 *
 * <p>Android kills the child processes of a background app that use much CPU
 * (GVXIP-006 F5). A foreground service keeps the app in the foreground state,
 * so a long guest command keeps running when the user leaves the app.
 *
 * <p>Start it with {@code adb shell am start-foreground-service -n
 * dev.gfire.gvx.sample/.RunService --esa args run,alpine:3,uname,-a}. The
 * output goes to logcat (tag {@code gvx}) and to {@code files/run.log}; the
 * last line is {@code exit N}.
 */
public final class RunService extends Service {
    private static final String TAG = "gvx";
    private static final String CHANNEL = "gvx";

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(
                new NotificationChannel(CHANNEL, "gvx", NotificationManager.IMPORTANCE_LOW));
        Notification n = new Notification.Builder(this, CHANNEL)
                .setContentTitle("gvx sandbox")
                .setSmallIcon(android.R.drawable.ic_media_play)
                .build();
        startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);

        String[] raw = intent == null ? null : intent.getStringArrayExtra("args");
        List<String> args = Arrays.asList(raw == null ? new String[] {"version"} : raw);
        new Thread(() -> {
            run(args);
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf(startId);
        }, "gvx-run").start();
        return START_NOT_STICKY;
    }

    private void run(List<String> args) {
        try (FileWriter log = new FileWriter(new File(getFilesDir(), "run.log"))) {
            Process p = Gvx.start(this, args);
            p.getOutputStream().close();
            try (BufferedReader out = new BufferedReader(new InputStreamReader(
                    p.getInputStream(), StandardCharsets.UTF_8))) {
                Thread err = new Thread(() -> copy(p, log), "gvx-stderr");
                err.start();
                String line;
                while ((line = out.readLine()) != null) {
                    write(log, line);
                }
                err.join();
            }
            write(log, "exit " + p.waitFor());
        } catch (Exception e) {
            Log.e(TAG, "rungv failed", e);
        }
    }

    private static void copy(Process p, FileWriter log) {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                p.getErrorStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = r.readLine()) != null) {
                write(log, line);
            }
        } catch (Exception e) {
            Log.e(TAG, "read stderr", e);
        }
    }

    private static void write(FileWriter log, String line) {
        Log.i(TAG, line);
        synchronized (log) {
            try {
                log.write(line + "\n");
                log.flush();
            } catch (Exception e) {
                Log.e(TAG, "write run.log", e);
            }
        }
    }
}
