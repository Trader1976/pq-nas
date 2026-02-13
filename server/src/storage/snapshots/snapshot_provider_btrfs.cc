#include "snapshot_provider.h"

#include <sys/wait.h>
#include <unistd.h>

#include <vector>
#include <string>
#include <sstream>

#include "../../audit_fields.h"

namespace pqnas::snapshots {

static bool run_cmd_capture_stderr(const std::vector<std::string>& argv, std::string& err) {
    err.clear();
    if (argv.empty()) { err = "empty argv"; return false; }

    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const auto& s : argv) cargv.push_back(const_cast<char*>(s.c_str()));
    cargv.push_back(nullptr);

    int pipefd[2];
    if (pipe(pipefd) != 0) { err = "pipe() failed"; return false; }

    pid_t pid = fork();
    if (pid < 0) {
        ::close(pipefd[0]); ::close(pipefd[1]);
        err = "fork() failed";
        return false;
    }

    if (pid == 0) {
        dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        execvp(cargv[0], cargv.data());
        _exit(127);
    }

    ::close(pipefd[1]);
    char buf[4096];
    std::string out;
    for (;;) {
        ssize_t n = read(pipefd[0], buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, buf + n);
    }
    ::close(pipefd[0]);

    int st = 0;
    waitpid(pid, &st, 0);

    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        err = pqnas::shorten(out, 400);
        return false;
    }
    return true;
}

class BtrfsProvider final : public SnapshotProvider {
public:
    CmdResult snapshot_ro(const std::string& src, const std::string& dst) override {
        CmdResult r;
        r.ok = run_cmd_capture_stderr({"btrfs","subvolume","snapshot","-r", src, dst}, r.err);
        return r;
    }

    CmdResult delete_subvol(const std::string& path) override {
        CmdResult r;
        r.ok = run_cmd_capture_stderr({"btrfs","subvolume","delete", path}, r.err);
        return r;
    }
};

std::unique_ptr<SnapshotProvider> make_btrfs_provider() {
    return std::make_unique<BtrfsProvider>();
}

} // namespace pqnas::snapshots
