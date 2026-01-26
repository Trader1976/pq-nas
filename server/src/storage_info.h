#pragma once
#include <string>
#include <vector>

namespace pqnas {

    struct StorageInfo {
        std::string root;          // the path we probed (e.g. build/bin/data or /srv/pqnas)
        std::string mountpoint;    // mountpoint that contains root
        std::string source;        // device/source from mountinfo (may be empty)
        std::string fstype;        // ext4/xfs/btrfs/zfs/...
        std::string options;       // mount options (comma-separated)
        bool prjquota_enabled = false; // true if mount options include prjquota/pquota
    };

    bool get_storage_info(const std::string& root, StorageInfo* out, std::string* err);

} // namespace pqnas
