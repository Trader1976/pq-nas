#pragma once
#include <memory>
#include <string>

namespace pqnas::snapshots {

    struct CmdResult {
        bool ok = false;
        std::string err;   // stderr (shortened) on failure
    };

    class SnapshotProvider {
    public:
        virtual ~SnapshotProvider() = default;

        virtual CmdResult snapshot_ro(const std::string& src, const std::string& dst) = 0;
        virtual CmdResult delete_subvol(const std::string& path) = 0;
    };

    std::unique_ptr<SnapshotProvider> make_btrfs_provider();

} // namespace pqnas::snapshots
