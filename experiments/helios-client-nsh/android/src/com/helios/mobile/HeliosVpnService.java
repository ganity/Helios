package com.helios.mobile;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

/** Application-private service. The activity must obtain VPN consent before starting it. */
public final class HeliosVpnService extends VpnService {
    public static final String NODE = "node";
    public static final String STOP = "com.helios.mobile.STOP";
    private static volatile String status = "未连接";
    private static volatile boolean active;
    public static String getStatus() { return status; }
    public static boolean isActive() { return active; }
    public static void authorizationPending() { status = "等待系统 VPN 授权"; }
    public static void authorizationDenied() { status = "VPN 授权已取消"; }
    public static void requestFailed(Exception error) { status = "启动失败：" + error.getMessage(); }
    public void connected() { if (!stopping) status = "已连接 · 全部代理"; }
    private volatile boolean stopping;
    private Thread worker;

    static { System.loadLibrary("nsh"); }
    private native void nativeRun(int fd, String nodeJson);

    // Called by the Rust worker through JNI; keep its name when minifying.
    public boolean isStopping() { return stopping; }

    @Override public synchronized int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null || STOP.equals(intent.getAction())) {
            stopping = true;
            stopSelf();
            return START_NOT_STICKY;
        }
        if (active) return START_NOT_STICKY;
        String node = intent.getStringExtra(NODE);
        if (node == null || node.isEmpty()) { stopSelf(); return START_NOT_STICKY; }
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel("vpn", "VPN connection", NotificationManager.IMPORTANCE_LOW));
        Notification notification = new Notification.Builder(this, "vpn")
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("Helios")
            .setContentText("VPN service running")
            .setContentIntent(PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT))
            .addAction(new Notification.Action.Builder(null, "断开",
                PendingIntent.getService(this, 1, new Intent(this, HeliosVpnService.class).setAction(STOP),
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT)).build())
            .setOngoing(true).build();
        startForeground(1, notification);
        active = true;
        status = "正在连接并验证节点";
        stopping = false;
        worker = new Thread(() -> {
            try (ParcelFileDescriptor tun = new Builder()
                    .setSession("Helios").setMtu(1500)
                    .addAddress("10.88.0.2", 32)
                    .addAddress("fd88::2", 128)
                    .addRoute("0.0.0.0", 0).addRoute("::", 0)
                    .addDnsServer("1.1.1.1").establish()) {
                if (tun == null) throw new IllegalStateException("VPN consent was revoked");
                if (!stopping) nativeRun(tun.getFd(), node);
            } catch (Exception error) {
                if (!stopping) status = "连接失败：" + error.getMessage();
                if (!stopping) nativeRecordError(status);
                Log.e("Helios", "VPN stopped with an error", error);
            } finally {
                if (stopping) status = "未连接";
                stopping = true;
                active = false;
                stopForeground(STOP_FOREGROUND_REMOVE);
                stopSelf();
            }
        }, "helios-vpn");
        worker.start();
        return START_NOT_STICKY;
    }

    private native void nativeRecordError(String message);

    @Override public void onRevoke() { stopping = true; status = "正在断开"; stopSelf(); }
    @Override public void onDestroy() {
        stopping = true;
        if (active) status = "正在断开";
        super.onDestroy();
    }
}
