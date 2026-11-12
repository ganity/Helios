package com.helios.mobile;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import com.longbridge.nsh.NshView;

/** Android consent and service lifecycle; the app UI is shared Rust NSH code. */
public final class MainActivity extends Activity {
    private NshView view;
    private String pendingNode;
    private native void nativeAttach();
    private native void nativeDetach();
    private native void nativeOpenLink(String link);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        view = new NshView(this);
        setContentView(view);
        nativeAttach();
        view.runRustApp("nsh");
        if (state != null) pendingNode = state.getString("pendingNode");
        receiveLink(getIntent());
    }

    private void receiveLink(Intent intent) {
        if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null
                && "helios".equals(intent.getData().getScheme())) {
            String link = intent.getData().toString();
            if (link.length() <= 16384) nativeOpenLink(link);
        }
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        receiveLink(intent);
    }

    public void requestConnect(String node) {
        runOnUiThread(() -> {
            if (isFinishing() || pendingNode != null || HeliosVpnService.isActive()) return;
            pendingNode = node;
            HeliosVpnService.authorizationPending();
            try {
                Intent consent = VpnService.prepare(this);
                if (consent == null) startVpn();
                else startActivityForResult(consent, 42);
            } catch (Exception error) {
                pendingNode = null;
                HeliosVpnService.requestFailed(error);
            }
        });
    }

    public String vpnStatus() { return HeliosVpnService.getStatus(); }

    private void startVpn() {
        String node = pendingNode;
        pendingNode = null;
        if (node != null) {
            try {
                startForegroundService(new Intent(this, HeliosVpnService.class)
                    .putExtra(HeliosVpnService.NODE, node));
            } catch (Exception error) { HeliosVpnService.requestFailed(error); }
        }
    }

    public void requestDisconnect() {
        runOnUiThread(() -> {
            if (pendingNode != null) HeliosVpnService.authorizationDenied();
            pendingNode = null;
            stopService(new Intent(this, HeliosVpnService.class));
        });
    }

    @Override protected void onSaveInstanceState(Bundle state) {
        state.putString("pendingNode", pendingNode);
        super.onSaveInstanceState(state);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 42) {
            if (result == RESULT_OK) startVpn();
            else {
                pendingNode = null;
                HeliosVpnService.authorizationDenied();
            }
        }
    }

    @Override protected void onDestroy() {
        nativeDetach();
        if (view != null) view.destroy();
        super.onDestroy();
    }
}
