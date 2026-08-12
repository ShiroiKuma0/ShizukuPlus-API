package rikka.shizuku.server;

import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SELinux;
import android.os.SystemProperties;
import android.system.Os;

import androidx.annotation.CallSuper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

import moe.shizuku.server.IRemoteProcess;
import moe.shizuku.server.IShizukuApplication;
import moe.shizuku.server.IShizukuService;
import moe.shizuku.server.IShizukuServiceConnection;
import af.shizuku.common.compat.Android17Compat;
import rikka.rish.RishConfig;
import rikka.rish.RishService;
import rikka.shizuku.ShizukuApiConstants;
import rikka.shizuku.server.api.RemoteProcessHolder;
import rikka.shizuku.server.util.Logger;
import rikka.shizuku.server.util.OsUtils;
import af.shizuku.common.util.UserHandleCompat;

public abstract class Service<
        UserServiceMgr extends UserServiceManager,
        ClientMgr extends ClientManager<ConfigMgr>,
        ConfigMgr extends ConfigManager> extends IShizukuService.Stub {

    private final UserServiceMgr userServiceManager;
    private final ConfigMgr configManager;
    private final ClientMgr clientManager;
    private final RishService rishService;

    protected static final Logger LOGGER = new Logger("Service");

    public Service() {
        RishConfig.init(ShizukuApiConstants.BINDER_DESCRIPTOR, 30000);

        userServiceManager = onCreateUserServiceManager();
        configManager = onCreateConfigManager();
        clientManager = onCreateClientManager();
        rishService = new RishService() {

            @Override
            public void enforceCallingPermission(String func) {
                Service.this.enforceCallingPermission(func);
            }
        };
    }

    public abstract UserServiceMgr onCreateUserServiceManager();

    public abstract ClientMgr onCreateClientManager();

    public abstract ConfigMgr onCreateConfigManager();

    public final UserServiceMgr getUserServiceManager() {
        return userServiceManager;
    }

    public final ClientMgr getClientManager() {
        return clientManager;
    }

    public ConfigMgr getConfigManager() {
        return configManager;
    }

    public boolean checkCallerManagerPermission(String func, int callingUid, int callingPid) {
        return false;
    }

    public final void enforceManagerPermission(String func) {
        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();

        if (callingPid == Os.getpid()) {
            return;
        }

        if (checkCallerManagerPermission(func, callingUid, callingPid)) {
            return;
        }

        String msg = "Permission Denial: " + func + " from pid="
                + Binder.getCallingPid()
                + " is not manager ";
        LOGGER.w(msg);
        throw new SecurityException(msg);
    }

    public boolean checkCallerPermission(String func, int callingUid, int callingPid, @Nullable ClientRecord clientRecord) {
        return false;
    }

    public final void enforceCallingPermission(String func) {
        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();

        if (callingUid == OsUtils.getUid()) {
            return;
        }

        ClientRecord clientRecord = clientManager.findClient(callingUid, callingPid);

        if (checkCallerPermission(func, callingUid, callingPid, clientRecord)) {
            return;
        }

        if (clientRecord == null) {
            String msg = "Permission Denial: " + func + " from pid="
                    + Binder.getCallingPid()
                    + " is not an attached client";
            LOGGER.w(msg);
            throw new SecurityException(msg);
        }

        if (!clientRecord.allowed) {
            String msg = "Permission Denial: " + func + " from pid="
                    + Binder.getCallingPid()
                    + " requires permission";
            LOGGER.w(msg);
            throw new SecurityException(msg);
        }
    }

    public final void transactRemote(Parcel data, Parcel reply, int flags) throws RemoteException {
        enforceCallingPermission("transactRemote");

        IBinder targetBinder = data.readStrongBinder();
        // Caller can write a null strong binder into the transact payload; fail with a
        // clear error instead of an opaque NPE on getInterfaceDescriptor() below.
        if (targetBinder == null) {
            throw new IllegalArgumentException("transactRemote: null target binder");
        }
        int targetCode = data.readInt();
        int targetFlags;

        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();
        ClientRecord clientRecord = clientManager.findClient(callingUid, callingPid);

        if (clientRecord != null && clientRecord.apiVersion >= 13) {
            targetFlags = data.readInt();
        } else {
            targetFlags = flags;
        }

        String descriptor = targetBinder.getInterfaceDescriptor();
        
        // AIDL Logging (Issue #199)
        if (checkPlusFeatureEnabled("binder_logging")) {
            LOGGER.i("AIDL: uid=%d pkg=%s descriptor=%s code=%d", 
                callingUid, (clientRecord != null ? clientRecord.packageName : "unknown"), 
                descriptor, targetCode);
        }

        // Binder Firewall (Issue #199)
        if (checkPlusFeatureEnabled("binder_firewall")) {
            if (isBinderCallBlocked(callingUid, descriptor, targetCode)) {
                LOGGER.w("Firewall: Blocked transaction %s code %d from uid %d", descriptor, targetCode, callingUid);
                throw new SecurityException("Binder Firewall: Transaction blocked by Shizuku+ policy");
            }
        }

        // Shadow Binder (Issue #199) - optional interception point
        if (checkPlusFeatureEnabled("shadow_binder")) {
            if (handleShadowBinderTransaction(targetBinder, targetCode, data, reply, targetFlags)) {
                return;
            }
        }

        Parcel newData = Parcel.obtain();
        try {
            newData.appendFrom(data, data.dataPosition(), data.dataAvail());
        } catch (Throwable tr) {
            LOGGER.w(tr, "appendFrom");
            return;
        }
        
        long startTime = System.nanoTime();
        try {
            long id = Binder.clearCallingIdentity();
            targetBinder.transact(targetCode, newData, reply, targetFlags);
            Binder.restoreCallingIdentity(id);
        } finally {
            newData.recycle();
            long durationNs = System.nanoTime() - startTime;
            if (checkPlusFeatureEnabled("binder_profiler")) {
                recordTransactionMetrics(clientRecord, descriptor, targetCode, durationNs);
            }
        }
    }

    /**
     * System Health & Binder Profiler (Issue #211)
     */
    protected void recordTransactionMetrics(ClientRecord clientRecord, String descriptor, int code, long durationNs) {
        String pkg = clientRecord != null ? clientRecord.packageName : "unknown";
        LOGGER.i("PROFILER: pkg=%s desc=%s code=%d latency_ms=%.2f", pkg, descriptor, code, durationNs / 1000000.0f);
    }

    /**
     * Shadow Binder (Issue #199)
     * Allows intercepting and mocking system binder calls.
     */
    protected boolean handleShadowBinderTransaction(IBinder target, int code, Parcel data, Parcel reply, int flags) {
        // To be implemented by subclasses if shadow binder is active
        return false;
    }

    /**
     * Binder Firewall (Issue #199)
     * Checks if a binder transaction should be blocked based on UID and descriptor.
     */
    protected boolean isBinderCallBlocked(int uid, String descriptor, int code) {
        // Example: Block apps from turning off Bluetooth or WiFi via Shizuku if they aren't authorized
        if (descriptor == null) return false;
        
        // Stub for dynamic policy checking
        return false;
    }

    @Override
    public final int getVersion() {
        enforceCallingPermission("getVersion");
        return ShizukuApiConstants.SERVER_VERSION;
    }

    @Override
    public final int getUid() {
        enforceCallingPermission("getUid");
        return Os.getuid();
    }

    @Override
    public final int checkPermission(String permission) throws RemoteException {
        enforceCallingPermission("checkPermission");
        return Android17Compat.checkPermission(permission, Os.getuid());
    }

    @Override
    public final String getSELinuxContext() {
        enforceCallingPermission("getSELinuxContext");

        try {
            return SELinux.getContext();
        } catch (Throwable tr) {
            throw new IllegalStateException(tr.getMessage());
        }
    }

    @Override
    public final String getSystemProperty(String name, String defaultValue) {
        enforceCallingPermission("getSystemProperty");

        try {
            return SystemProperties.get(name, defaultValue);
        } catch (Throwable tr) {
            throw new IllegalStateException(tr.getMessage());
        }
    }

    @Override
    public final void setSystemProperty(String name, String value) {
        enforceCallingPermission("setSystemProperty");

        try {
            SystemProperties.set(name, value);
        } catch (Throwable tr) {
            throw new IllegalStateException(tr.getMessage());
        }
    }

    @Override
    public final int removeUserService(IShizukuServiceConnection conn, Bundle options) {
        enforceCallingPermission("removeUserService");

        return userServiceManager.removeUserService(conn, options);
    }

    @Override
    public final int addUserService(IShizukuServiceConnection conn, Bundle options) {
        enforceCallingPermission("addUserService");

        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();
        int callingApiVersion;

        ClientRecord clientRecord = clientManager.findClient(callingUid, callingPid);
        if (clientRecord == null) {
            callingApiVersion = ShizukuApiConstants.SERVER_VERSION;
        } else {
            callingApiVersion = clientRecord.apiVersion;
        }
        return userServiceManager.addUserService(conn, options, callingApiVersion);
    }

    @Override
    public void attachUserService(IBinder binder, Bundle options) {
        userServiceManager.attachUserService(binder, options);
    }

    @Override
    public final boolean checkSelfPermission() {
        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();

        if (callingUid == OsUtils.getUid() || callingPid == OsUtils.getPid()) {
            return true;
        }

        return clientManager.requireClient(callingUid, callingPid).allowed;
    }

    @Override
    public final void requestPermission(int requestCode) {
        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();
        int userId = UserHandleCompat.getUserId(callingUid);

        if (callingUid == OsUtils.getUid() || callingPid == OsUtils.getPid()) {
            return;
        }

        ClientRecord clientRecord = clientManager.requireClient(callingUid, callingPid);

        if (clientRecord.allowed) {
            clientRecord.dispatchRequestPermissionResult(requestCode, true);
            return;
        }

        ConfigPackageEntry entry = configManager.find(callingUid);
        if (entry != null && entry.isDenied()) {
            clientRecord.dispatchRequestPermissionResult(requestCode, false);
            return;
        }

        showPermissionConfirmation(requestCode, clientRecord, callingUid, callingPid, userId);
    }

    public abstract void showPermissionConfirmation(
            int requestCode, @NonNull ClientRecord clientRecord, int callingUid, int callingPid, int userId);

    @Override
    public final boolean shouldShowRequestPermissionRationale() {
        int callingUid = Binder.getCallingUid();
        int callingPid = Binder.getCallingPid();

        if (callingUid == OsUtils.getUid() || callingPid == OsUtils.getPid()) {
            return true;
        }

        clientManager.requireClient(callingUid, callingPid);

        ConfigPackageEntry entry = configManager.find(callingUid);
        return entry != null && entry.isDenied();
    }

    public IRemoteProcess newProcessInternal(String[] cmd, String[] env, String dir) {
        enforceCallingPermission("newProcess");

        LOGGER.d("newProcess: uid=%d, cmd=%s, env=%s, dir=%s", Binder.getCallingUid(), Arrays.toString(cmd), Arrays.toString(env), dir);

        java.lang.Process process;
        try {
            process = Runtime.getRuntime().exec(cmd, env, dir != null ? new File(dir) : null);
        } catch (IOException e) {
            throw new IllegalStateException(e.getMessage());
        }

        ClientRecord clientRecord = clientManager.findClient(Binder.getCallingUid(), Binder.getCallingPid());
        IBinder token = clientRecord != null ? clientRecord.client.asBinder() : null;

        return new RemoteProcessHolder(process, token);
    }

    public boolean checkPlusFeatureEnabled(String key) {
        return true;
    }

    @CallSuper
    @Override
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        // Every client vintage writes the SAME interface token: ShizukuApiConstants.BINDER_DESCRIPTOR
        // *is* the literal "moe.shizuku.server.IShizukuService". So there was never a legacy/new
        // distinction to draw from the descriptor, and the branch that tried to draw one could not
        // reach its "new" side — which was the only place code 17 (v13 attachApplication) was handled.
        //
        // enforceInterface() is public SDK, and it both validates the token and leaves the read cursor
        // exactly where the raw cases below expect it. It replaces a readInterfaceTokenCompat() that
        // reflected for a non-existent Parcel.readInterfaceToken() and returned "" on any failure —
        // making every comparison false and skipping this entire block, both attachApplication entry
        // points included, for every caller that has ever connected.
        data.setDataPosition(0);
        boolean ourToken;
        try {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            ourToken = true;
        } catch (SecurityException e) {
            ourToken = false;
            data.setDataPosition(0); // leave the parcel exactly as we found it
        }

        if (ourToken) {
            if (code == ShizukuApiConstants.BINDER_TRANSACTION_transact) {
                transactRemote(data, reply, flags);
                return true;
            }

            // Both attach codes are hand-written raw transactions in Shizuku.java rather than proxy
            // calls, and both must be intercepted for EVERY client regardless of vintage.
            //
            // Raw 17 is the one that mattered: the AIDL declares
            // shouldShowRequestPermissionRationale() = 16, and AIDL wire codes are
            // FIRST_CALL_TRANSACTION + id with FIRST_CALL_TRANSACTION == 1, so that method also
            // answers to 17. Left to the generated stub, a v13 client's attach was dispatched to it,
            // which calls requireClient() and throws "Not an attached client" at the very client
            // trying to become one — every modern rikka-API client, not just one app.
            switch (code) {
                case 17: { // attachApplication, v13+ payload: (IBinder, int hasArgs, Bundle?)
                    IBinder application = data.readStrongBinder();
                    Bundle args = data.readInt() != 0 ? Bundle.CREATOR.createFromParcel(data) : null;
                    attachApplication(IShizukuApplication.Stub.asInterface(application), args);
                    reply.writeNoException();
                    return true;
                }
                case 14: { // attachApplication, v11 payload: (IBinder, String packageName)
                    IBinder application = data.readStrongBinder();
                    Bundle args = new Bundle();
                    args.putString(ShizukuApiConstants.ATTACH_APPLICATION_PACKAGE_NAME, data.readString());
                    args.putInt(ShizukuApiConstants.ATTACH_APPLICATION_API_VERSION, -1);
                    attachApplication(IShizukuApplication.Stub.asInterface(application), args);
                    reply.writeNoException();
                    return true;
                }
                // Pre-v11 clients send these as raw codes too, expecting the cursor to sit just after
                // the interface token — which is where enforceInterface() above leaves it.
                //
                // ⛔ A raw case here may ONLY name a code that no CURRENT AIDL method answers to,
                // because this switch runs before the generated stub and silently wins. Wire code is
                // FIRST_CALL_TRANSACTION + id, i.e. id + 1, so the live codes are getVersion 3,
                // getUid 4, checkPermission 5, newProcess 8, getSELinuxContext 9. Cases 2 and 7 are
                // free (no live method sits at id 1 or 6) and stay; the legacy cases for 3, 4 and 8
                // are gone because each shadowed a live method one slot along.
                //
                // Code 8 was the expensive one. A modern client calling newProcess transacts 8, was
                // answered with getSELinuxContext, and read that String back as a strong binder —
                // which yields null, so Shizuku.newProcess() returned null for EVERY caller and
                // ShizukuRemoteProcess threw "the privileged service could not start the command".
                // That is SHIZUKUPLUS-85, and it took the whole PrivilegedShell Shizuku tier with it:
                // "Grant now", "Make owner" and the updater all fell through to their no-privilege
                // fallbacks while the server was running perfectly.
                //
                // The collision is inherent — old wire 8 meant getSELinuxContext, new wire 8 means
                // newProcess — so it cannot be served both ways from one code. Current clients win:
                // the api library ships inside this app.
                case 2: // getVersion (legacy id 1)
                    reply.writeNoException();
                    reply.writeInt(getVersion());
                    return true;
                case 7: { // newProcess (legacy id 6)
                    String[] cmd = data.createStringArray();
                    String[] env = data.createStringArray();
                    String dir = data.readString();
                    IRemoteProcess process = newProcess(cmd, env, dir);
                    reply.writeNoException();
                    reply.writeStrongBinder(process != null ? process.asBinder() : null);
                    return true;
                }
            }

            // Not a raw code we handle: rewind before falling through, because BOTH fall-through paths
            // read the token themselves — RishService.onTransact calls data.enforceInterface() and so
            // does the AIDL-generated Stub.onTransact. Without this rewind, enforceInterface() above
            // turns every ordinary AIDL call into "Binder invocation to an incorrect interface"; the
            // dangling cursor was a latent second defect that only bites once the token read works.
            data.setDataPosition(0);
        }

        if (rishService.onTransact(code, data, reply, flags)) {
            return true;
        }
        // Belt and braces for the same cursor trap one layer down. Every RishService branch that
        // reads the parcel currently returns true, so this cannot fire today — but the class of bug
        // it guards is the one this method has now been fixed for twice, and a rish code added later
        // that enforces the token and then declines would hand super.onTransact a dangling cursor.
        data.setDataPosition(0);
        return super.onTransact(code, data, reply, flags);
    }
}
