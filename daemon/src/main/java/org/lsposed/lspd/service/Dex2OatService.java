/*
 * This file is part of LSPosed.
 *
 * LSPosed is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * LSPosed is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with LSPosed.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2022 LSPosed Contributors
 */

package org.lsposed.lspd.service;

import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_CRASHED;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_MOUNT_FAILED;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_OK;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_SELINUX_PERMISSIVE;
import static org.lsposed.lspd.ILSPManagerService.DEX2OAT_SEPOLICY_INCORRECT;

import static org.lsposed.lspd.service.DenylistManager.isInDenylist;
import static org.lsposed.lspd.service.DenylistManager.isInDenylistFromClasspathDir;

import android.net.LocalServerSocket;
import android.os.Build;
import android.os.FileObserver;
import android.os.Process;
import android.os.SELinux;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

@RequiresApi(Build.VERSION_CODES.Q)
public class Dex2OatService implements Runnable {
    private static final String TAG = "LSPosedDex2Oat";
    private static final String WRAPPER32 = "bin/dex2oat32";
    private static final String WRAPPER64 = "bin/dex2oat64";
    private static final String HOOKER32 = "bin/liboat_hook32.so";
    private static final String HOOKER64 = "bin/liboat_hook64.so";

    private final String[] dex2oatArray = new String[6];
    private final FileDescriptor[] fdArray = new FileDescriptor[6];
    private final FileObserver selinuxObserver;
    private int compatibility = DEX2OAT_OK;

    private void openDex2oat(int id, String path) {
        try {
            var fd = Os.open(path, OsConstants.O_RDONLY, 0);
            dex2oatArray[id] = path;
            fdArray[id] = fd;
        } catch (ErrnoException ignored) {
        }
    }

    public Dex2OatService() {
        if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
            openDex2oat(Process.is64Bit() ? 2 : 0, "/apex/com.android.runtime/bin/dex2oat");
            openDex2oat(Process.is64Bit() ? 3 : 1, "/apex/com.android.runtime/bin/dex2oatd");
        } else {
            openDex2oat(0, "/apex/com.android.art/bin/dex2oat32");
            openDex2oat(1, "/apex/com.android.art/bin/dex2oatd32");
            openDex2oat(2, "/apex/com.android.art/bin/dex2oat64");
            openDex2oat(3, "/apex/com.android.art/bin/dex2oatd64");
        }

        openDex2oat(4, "/data/adb/modules/zygisk_lsposed/bin/liboat_hook32.so");
        openDex2oat(5, "/data/adb/modules/zygisk_lsposed/bin/liboat_hook64.so");

        var enforce = Paths.get("/sys/fs/selinux/enforce");
        var policy = Paths.get("/sys/fs/selinux/policy");
        var list = new ArrayList<File>();
        list.add(enforce.toFile());
        list.add(policy.toFile());
        selinuxObserver = new FileObserver(list, FileObserver.CLOSE_WRITE) {
            @Override
            public synchronized void onEvent(int i, @Nullable String s) {
                Log.d(TAG, "SELinux status changed");
                if (compatibility == DEX2OAT_CRASHED) {
                    stopWatching();
                    return;
                }

                boolean enforcing = false;
                try (var is = Files.newInputStream(enforce)) {
                    enforcing = is.read() == '1';
                } catch (IOException ignored) {
                }

                if (!enforcing) {
                    if (compatibility == DEX2OAT_OK) doMount(false);
                    compatibility = DEX2OAT_SELINUX_PERMISSIVE;
                } else if (SELinux.checkSELinuxAccess("u:r:untrusted_app:s0",
                        "u:object_r:dex2oat_exec:s0", "file", "execute")
                        || SELinux.checkSELinuxAccess("u:r:untrusted_app:s0",
                        "u:object_r:dex2oat_exec:s0", "file", "execute_no_trans")) {
                    if (compatibility == DEX2OAT_OK) doMount(false);
                    compatibility = DEX2OAT_SEPOLICY_INCORRECT;
                } else if (compatibility != DEX2OAT_OK) {
                    doMount(true);
                    if (notMounted()) {
                        doMount(false);
                        compatibility = DEX2OAT_MOUNT_FAILED;
                        stopWatching();
                    } else {
                        compatibility = DEX2OAT_OK;
                    }
                }
            }

            @Override
            public void stopWatching() {
                super.stopWatching();
                Log.w(TAG, "SELinux observer stopped");
            }
        };
    }

    private boolean notMounted() {
        for (int i = 0; i < dex2oatArray.length && i < 4; i++) {
            var bin = dex2oatArray[i];
            if (bin == null) continue;
            try {
                var apex = Os.stat("/proc/1/root" + bin);
                var wrapper = Os.stat(i < 2 ? WRAPPER32 : WRAPPER64);
                if (apex.st_dev != wrapper.st_dev || apex.st_ino != wrapper.st_ino) {
                    Log.w(TAG, "Check mount failed for " + bin);
                    return true;
                }
            } catch (ErrnoException e) {
                Log.e(TAG, "Check mount failed for " + bin, e);
                return true;
            }
        }
        Log.d(TAG, "Check mount succeeded");
        return false;
    }

    private void doMount(boolean enabled) {
        doMountNative(enabled, dex2oatArray[0], dex2oatArray[1], dex2oatArray[2], dex2oatArray[3]);
    }

    public void start() {
        if (notMounted()) { // Already mounted when restart daemon
            doMount(true);
            if (notMounted()) {
                doMount(false);
                compatibility = DEX2OAT_MOUNT_FAILED;
                return;
            }
        }

        var thread = new Thread(this);
        thread.setName("dex2oat");
        thread.start();
        selinuxObserver.startWatching();
        selinuxObserver.onEvent(0, null);
    }

    private int readInt(InputStream is) throws IOException {
        byte[] intBytes = new byte[4];
        int bytesRead = is.read(intBytes);
        if (bytesRead != 4) {
            Log.w(TAG, "Failed to read a full 4-byte integer. Read " + bytesRead + " bytes.");

            return -1;
        }

        return ByteBuffer.wrap(intBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private void writeInt(OutputStream os, int val) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(val);

        os.write(buffer.array());
    }

    @Override
    public void run() {
        Log.i(TAG, "Dex2oat wrapper daemon start");
        var sockPath = getSockPath();
        Log.d(TAG, "wrapper path: " + sockPath);
        var xposed_file = "u:object_r:xposed_file:s0";
        var dex2oat_exec = "u:object_r:dex2oat_exec:s0";
        if (SELinux.checkSELinuxAccess("u:r:dex2oat:s0", dex2oat_exec,
                "file", "execute_no_trans")) {
            SELinux.setFileContext(WRAPPER32, dex2oat_exec);
            SELinux.setFileContext(WRAPPER64, dex2oat_exec);
            setSockCreateContext("u:r:dex2oat:s0");
        } else {
            SELinux.setFileContext(WRAPPER32, xposed_file);
            SELinux.setFileContext(WRAPPER64, xposed_file);
            setSockCreateContext("u:r:installd:s0");
        }
        SELinux.setFileContext(HOOKER32, xposed_file);
        SELinux.setFileContext(HOOKER64, xposed_file);
        try (var server = new LocalServerSocket(sockPath)) {
            setSockCreateContext(null);

            while (true) {
                var client = server.accept();
                if (client == null) {
                    Log.w(TAG, "Dex2oat wrapper daemon accept null client");
                    continue;
                }

                var is = client.getInputStream();
                if (is == null) {
                    Log.w(TAG, "Dex2oat wrapper daemon accept client without input stream");
                    client.close();
                    continue;
                }

                var os = client.getOutputStream();
                if (os == null) {
                    Log.w(TAG, "Dex2oat wrapper daemon accept client without output stream");
                    client.close();
                    continue;
                }

                int op = readInt(is);
                if (op < 0) {
                    Log.w(TAG, "Dex2oat wrapper daemon received incomplete or invalid operation code.");

                    client.close();

                    continue;
                }

                if (op == 1) {
                    /* INFO: Send liboat_hook.so file descriptor */
                    int id = readInt(is);
                    if (id < 0 || id >= dex2oatArray.length) {
                        Log.w(TAG, "Dex2oat wrapper daemon accept client with invalid id: " + id);

                        client.close();

                        continue;
                    }

                    var fd = new FileDescriptor[]{fdArray[id]};
                    client.setFileDescriptorsForSend(fd);

                    /* INFO: When sending file descriptors, you also send a small message,
                               for the dex2oat.cpp, it is reading a 4-byte integer, which
                               this line below is writing. It should not be tried to read
                               after reading the file descriptors. It is used to send the
                               fs, after all. */
                    writeInt(os, 1);

                    Log.d(TAG, "Sent fd of " + dex2oatArray[id]);
                } else if (op == 2) {
                    /* INFO: Check if process is in denylist */
                    int classpathDirLen = readInt(is);
                    if (classpathDirLen < 0) {
                        Log.w(TAG, "Dex2oat wrapper daemon received invalid classpath dir length: " + classpathDirLen);

                        client.close();

                        continue;
                    }

                    Log.d(TAG, "Received classpath dir length: " + classpathDirLen);
                    if (classpathDirLen < 0 || classpathDirLen > 1024) {
                        Log.w(TAG, "Dex2oat wrapper daemon received invalid classpath dir length: " + classpathDirLen);

                        client.close();

                        continue;
                    }

                    byte[] classpathDirBytes = new byte[classpathDirLen];
                    int bytesRead = is.read(classpathDirBytes);
                    if (bytesRead != classpathDirLen) {
                        Log.w(TAG, "Dex2oat wrapper daemon received incomplete process name. Expected: "
                                + classpathDirLen + ", Read: " + bytesRead);

                        client.close();

                        continue;
                    }

                    String classpathDirArg = new String(classpathDirBytes);
                    if (classpathDirArg.isEmpty() && classpathDirLen > 0) {
                        Log.w(TAG, "Dex2oat wrapper daemon received empty process name despite reported length: " + classpathDirLen);

                        client.close();

                        continue;
                    }

                    Log.d(TAG, "Received classpath dir: " + classpathDirArg);

                    boolean isDenied = isInDenylistFromClasspathDir(classpathDirArg);

                    writeInt(os, isDenied ? 1 : 0);
                    Log.d(TAG, "Process is "
                            + (isDenied ? "denied" : "allowed") + " for injected dex2oat");
                } else {
                    Log.w(TAG, "Dex2oat wrapper daemon received unknown operation: " + op);

                    client.close();

                    continue;
                }

                client.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Dex2oat wrapper daemon crashed", e);
            if (compatibility == DEX2OAT_OK) {
                doMount(false);
                compatibility = DEX2OAT_CRASHED;
            }
        }
    }

    public int getCompatibility() {
        return compatibility;
    }

    private native void doMountNative(boolean enabled,
                                      String r32, String d32, String r64, String d64);

    private static native boolean setSockCreateContext(String context);

    private native String getSockPath();
}
