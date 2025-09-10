package org.lsposed.lspd.util;

import static org.lsposed.lspd.service.ServiceManager.TAG;
import org.lsposed.lspd.service.ConfigFileManager;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import android.util.Log;

public class KsuAllowListLoader {
    private static final int FILE_MAGIC = 0x7f4b5355; // \x7fKSU
    private static final int KSU_MAX_PACKAGE_NAME = 256;
    private static final int KSU_MAX_GROUPS = 32;
    private static final int KSU_SELINUX_DOMAIN = 64;
    private static final int CURRENT_ALLOWLIST_VERSION = 3;
    private static final int CURRENT_APP_PROFILE_VERSION = 2;
    
    // Profile classes
    public static class AppProfile {
        public int version;
        public String key;
        public int currentUid;
        public boolean allowSu;
        public RpConfig rpConfig;
        public NrpConfig nrpConfig;
        
        public AppProfile() {
            this.key = "";
            this.rpConfig = new RpConfig();
            this.nrpConfig = new NrpConfig();
        }
    }
    
    public static class RpConfig {
        public boolean useDefault;
        public String templateName;
        public RootProfile profile;
        
        public RpConfig() {
            this.templateName = "";
            this.profile = new RootProfile();
        }
    }
    
    public static class NrpConfig {
        public boolean useDefault;
        public NonRootProfile profile;
        
        public NrpConfig() {
            this.profile = new NonRootProfile();
        }
    }
    
    public static class RootProfile {
        public int uid;
        public int gid;
        public int groupsCount;
        public int[] groups;
        public Capabilities capabilities;
        public String selinuxDomain;
        public int namespaces;
        
        public RootProfile() {
            this.groups = new int[KSU_MAX_GROUPS];
            this.capabilities = new Capabilities();
            this.selinuxDomain = "";
        }
    }
    
    public static class Capabilities {
        public long effective;
        public long permitted;
        public long inheritable;
    }
    
    public static class NonRootProfile {
        public boolean umountModules;
    }
    
    public static List<AppProfile> getAllowList() {
        List<AppProfile> profiles = new ArrayList<>();

        try (FileInputStream fis = new FileInputStream(ConfigFileManager.ksuAllowList)) {
            // Read and validate file header
            if (!validateFileHeader(fis)) {
                Log.e(TAG, "Invalid file header or version");
                return profiles;
            }
            
            // Read profiles
            int profileCount = 0;
            while (true) {
                AppProfile profile = new AppProfile();
                int ret = readAppProfile(fis, profile);
                if (ret <= 0) {
                    break;
                }
                profiles.add(profile);
                profileCount++;
                 Log.i(TAG, String.format("Profile %d: name=%s, uid=%d, allow_su=%d", 
                    profileCount, profile.key, profile.currentUid, 
                    profile.allowSu ? 1 : 0));
            }
            
            Log.i(TAG, "Total profiles loaded: " + profileCount);
            return profiles;
        } catch (FileNotFoundException e) {
            Log.e(TAG, "Allow list file not found: " + ConfigFileManager.ksuAllowList.getAbsolutePath());
            return profiles;
        } catch (IOException e) {
            Log.e(TAG, "IO error reading allow list: " + e.getMessage());
            return profiles;
        } catch (Exception e) {
            Log.e(TAG, "Error reading allow list: " + e.getMessage());
            return profiles;
        }
    }
    
    private static boolean validateFileHeader(FileInputStream fis) throws IOException {
        try {
            // Read magic number
            byte[] magicBytes = readExactBytes(fis, 4);
            if (magicBytes == null) return false;
            int fileMagic = bytesToInt(magicBytes);
            
            if (fileMagic != FILE_MAGIC) {
                Log.e(TAG, String.format("Invalid magic number. Expected: 0x%08X, Got: 0x%08X", 
                    FILE_MAGIC, fileMagic));
                return false;
            }
            
            // Read file version
            byte[] versionBytes = readExactBytes(fis, 4);
            if (versionBytes == null) return false;
            int fileVersion = bytesToInt(versionBytes);
            
            if (fileVersion != CURRENT_ALLOWLIST_VERSION) {
                Log.e(TAG, String.format("Unsupported version. Expected: %d, Got: %d", 
                    CURRENT_ALLOWLIST_VERSION, fileVersion));
                return false;
            }
            
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Error validating file header: " + e.getMessage());
            throw e;
        }
    }
    
    private static int readAppProfile(FileInputStream fis, AppProfile profile) throws IOException {
        try {
            // Read app profile version
            byte[] appProfileVersionBytes = readExactBytes(fis, 4);
            if (appProfileVersionBytes == null) return 0; // Normal EOF
            
            int appProfileVersion = bytesToInt(appProfileVersionBytes);
            if (appProfileVersion != CURRENT_APP_PROFILE_VERSION) {
                // This might be end of file or corrupted data
                return 0;
            }
            
            // Read key
            byte[] keyBytes = readExactBytes(fis, KSU_MAX_PACKAGE_NAME);
            if (keyBytes == null) return 0;
            profile.key = bytesToString(keyBytes);
            
            // Read current_uid
            byte[] uidBytes = readExactBytes(fis, 4);
            if (uidBytes == null) return 0;
            profile.currentUid = bytesToInt(uidBytes);
            
            // Read allow_su
            int boolByte = fis.read();
            if (boolByte == -1) return 0;
            profile.allowSu = boolByte == 1;
            
            // Read padding (7 bytes)
            if (skipBytes(fis, 7) != 7) return 0;
            
            if (profile.allowSu) {
                return readRootProfile(fis, profile);
            } else {
                return readNonRootProfile(fis, profile);
            }
            
        } catch (IOException e) {
            // Normal end of file or incomplete read
           throw e;
        }
    }
    
    private static int readRootProfile(FileInputStream fis, AppProfile profile) throws IOException {
        try {
            // Read rp_config.use_default
            int boolByte = fis.read();
            if (boolByte == -1) return 0;
            profile.rpConfig.useDefault = boolByte == 1;
            
            // Read rp_config.template_name
            byte[] templateBytes = readExactBytes(fis, KSU_MAX_PACKAGE_NAME);
            if (templateBytes == null) return 0;
            profile.rpConfig.templateName = bytesToString(templateBytes);
            
            // Read padding (7 bytes)
            if (skipBytes(fis, 7) != 7) return 0;
            
            // Read root_profile fields
            byte[] rootUidBytes = readExactBytes(fis, 4);
            if (rootUidBytes == null) return 0;
            profile.rpConfig.profile.uid = bytesToInt(rootUidBytes);
            
            byte[] gidBytes = readExactBytes(fis, 4);
            if (gidBytes == null) return 0;
            profile.rpConfig.profile.gid = bytesToInt(gidBytes);
            
            byte[] countBytes = readExactBytes(fis, 4);
            if (countBytes == null) return 0;
            profile.rpConfig.profile.groupsCount = bytesToInt(countBytes);
            
            // Read groups
            int groupsToRead = Math.min(profile.rpConfig.profile.groupsCount, KSU_MAX_GROUPS);
            for (int i = 0; i < groupsToRead; i++) {
                byte[] groupBytes = readExactBytes(fis, 4);
                if (groupBytes == null) return 0;
                profile.rpConfig.profile.groups[i] = bytesToInt(groupBytes);
            }
            
            // Skip remaining groups
            int remainingGroups = KSU_MAX_GROUPS - groupsToRead;
            if (skipBytes(fis, remainingGroups * 4) != remainingGroups * 4) return 0;
            
            // Read padding (4 bytes)
            if (skipBytes(fis, 4) != 4) return 0;
            
            // Read capabilities
            profile.rpConfig.profile.capabilities.effective = readLong(fis);
            profile.rpConfig.profile.capabilities.permitted = readLong(fis);
            profile.rpConfig.profile.capabilities.inheritable = readLong(fis);
            
            // Read selinux_domain
            byte[] domainBytes = readExactBytes(fis, KSU_SELINUX_DOMAIN);
            if (domainBytes == null) return 0;
            profile.rpConfig.profile.selinuxDomain = bytesToString(domainBytes);
            
            // Read namespaces
            byte[] nsBytes = readExactBytes(fis, 4);
            if (nsBytes == null) return 0;
            profile.rpConfig.profile.namespaces = bytesToInt(nsBytes);
            
            // Read final padding (4 bytes)
            if (skipBytes(fis, 4) != 4) return 0;
            
            return 1; // Success
        } catch (IOException e) {
            throw e;
        }
    }
    
    private static int readNonRootProfile(FileInputStream fis, AppProfile profile) throws IOException {
        try {
            // Read nrpConfig.use_default
            int boolByte = fis.read();
            if (boolByte == -1) return 0;
            profile.nrpConfig.useDefault = boolByte == 1;
            
            // Read umount_modules
            boolByte = fis.read();
            if (boolByte == -1) return 0;
            profile.nrpConfig.profile.umountModules = boolByte == 1;
            
            // Skip remaining bytes (503 bytes)
            if (skipBytes(fis, 502) != 502) return 0;
            
            return 1; // Success
        } catch (IOException e) {
            throw e;
        }
    }
    
    // Utility methods
    private static byte[] readExactBytes(FileInputStream fis, int count) throws IOException {
        try {
            if (count <= 0) return new byte[0];
            
            byte[] bytes = new byte[count];
            int totalRead = 0;
            
            while (totalRead < count) {
                int bytesRead = fis.read(bytes, totalRead, count - totalRead);
                if (bytesRead == -1) {
                    // End of file reached - this is normal
                    return null;
                }
                totalRead += bytesRead;
            }
            
            return bytes;
        } catch (IOException e) {
            Log.e(TAG, "Error reading bytes: " + e.getMessage());
            throw e;
        }
    }
    
    private static long skipBytes(FileInputStream fis, long count) throws IOException {
        try {
            if (count <= 0) return 0;
            
            long totalSkipped = 0;
            while (totalSkipped < count) {
                long skipped = fis.skip(count - totalSkipped);
                if (skipped == 0) {
                    // If skip returns 0, try reading a byte to see if we're at EOF
                    int nextByte = fis.read();
                    if (nextByte == -1) {
                        break; // EOF reached
                    } else {
                        totalSkipped++;
                    }
                } else {
                    totalSkipped += skipped;
                }
            }
            return totalSkipped;
        } catch (IOException e) {
            Log.e(TAG, "Error skipping bytes: " + e.getMessage());
            throw e;
        }
    }
    
    private static long readLong(FileInputStream fis) throws IOException {
        try {
            byte[] bytes = readExactBytes(fis, 8);
            if (bytes == null) return 0; // EOF is normal
            return bytesToLong(bytes);
        } catch (IOException e) {
            Log.e(TAG, "Error reading long: " + e.getMessage());
            throw e;
        }
    }
    
    private static String bytesToString(byte[] bytes) {
        if (bytes == null) return "";
        return new String(bytes).trim().replaceAll("\0.*", "");
    }
    
    private static int bytesToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) | 
               ((bytes[1] & 0xFF) << 8) | 
               ((bytes[2] & 0xFF) << 16) | 
               ((bytes[3] & 0xFF) << 24);
    }
    
    private static long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        return buffer.getLong();
    }
}