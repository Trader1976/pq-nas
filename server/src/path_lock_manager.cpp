#include "path_lock_manager.h"

#include <algorithm>

namespace pqnas {

/*
Architecture notes
==================

Purpose
-------
PathLockManager serializes overlapping write operations in the Files API.
It is designed to prevent concurrent PUT / MOVE / DELETE requests from
mutating the same logical file or subtree at the same time.

This is a correctness layer, not a permission layer:
- authorization still happens in the request handlers
- path normalization still happens in the request handlers
- this manager only answers: "may this request mutate these logical paths now?"

Why subtree-aware locking exists
--------------------------------
PQ-NAS now supports metadata-backed logical paths, directory moves, subtree
deletes, and path conflict rules such as:
- file vs file
- file vs dir child
- dir vs descendant
- move source vs destination subtree overlap

Without serialization, these operations can race and leave the filesystem and
file_locations metadata out of sync. Example bad races:
- MOVE docs -> archive/docs  racing with  DELETE docs
- PUT docs/a.txt            racing with  MOVE docs -> moved/docs
- PUT file.txt              racing with  PUT file.txt

Locking overlapping logical paths ensures the handlers see a stable namespace
while they perform metadata + filesystem mutations.

Scope
-----
This implementation is process-local. That is intentional for the current
deployment model where one pqnas_server process handles requests.

It does NOT coordinate across:
- multiple server processes
- multiple machines / clustered nodes

If PQ-NAS later becomes multi-process or distributed, this abstraction will
need a different backend (e.g. SQLite advisory row locks, file locks, Redis,
or another distributed lock service).

Lock granularity
----------------
Locks are exclusive-only for now: there is no separate shared/read mode.

Two logical paths conflict when:
- they are equal, OR
- one is a parent prefix of the other, using "/" as a path-segment boundary

Examples:
- "docs" conflicts with "docs"
- "docs" conflicts with "docs/a.txt"
- "docs/sub" conflicts with "docs/sub/file.bin"
- "docs" does NOT conflict with "docs2"
- "a.txt" does NOT conflict with "a.txt.bak"

This makes the lock manager subtree-aware while remaining simple.

Per-user isolation
------------------
Locks are isolated by fingerprint ("fp"). That means:
- overlapping paths for the SAME user conflict
- overlapping paths for DIFFERENT users do not conflict

This is important because each user has an independent logical namespace.

Canonicalization
----------------
The handlers pass already-normalized logical paths into lock_paths(). This file
still canonicalizes the vector of requested paths by:
- sorting
- removing duplicates

This gives stable acquisition order and avoids self-deadlock-like behavior when
a caller accidentally requests the same path twice.

Deadlock avoidance
------------------
lock_paths() acquires all requested paths atomically under one mutex after
sorting. Since there is only one internal mutex and one global held_ registry,
and because requested paths are canonicalized, there is no multi-lock cycle in
this implementation.

Fairness
--------
Fairness is "best effort" only. Waiters are awakened via notify_all() and race
to reacquire mu_. This is acceptable for now because:
- critical sections are short
- path sets are small
- correctness matters more than strict fairness

If starvation ever becomes visible under heavy load, queue-based admission can
be added later.

Complexity
----------
Current implementation scans held_ linearly:
- acquisition: O(requested_paths * held_paths)
- unlock: O(requested_paths * held_paths)

That is fine for the current expected request volume and small number of
simultaneous overlapping writers. If needed later, held_ can be replaced with
a more structured index.

Important semantic note
-----------------------
This layer serializes overlapping writes, but it does NOT freeze namespace
history.

Example:
1. MOVE docs -> moved/docs acquires the lock on "docs" and completes
2. PUT docs/new.txt waits
3. after MOVE releases, PUT acquires the lock and recreates a fresh "docs"

This is valid and deterministic. If stricter stale-request semantics are
desired later, handlers should add post-lock revalidation of parent/path state.

Guard lifetime
--------------
Guard is RAII-based:
- lock_paths() returns a Guard
- when the Guard is destroyed, held paths are released
- move construction / move assignment transfer ownership safely

This keeps handler code simple and makes it hard to forget unlocks on early
returns or exceptions.
*/

namespace {
PathLockManager g_path_lock_manager;
}

PathLockManager* get_path_lock_manager() {
    return &g_path_lock_manager;
}

PathLockManager::Guard::Guard(PathLockManager* mgr,
                              std::string fp,
                              std::vector<std::string> paths)
    : mgr_(mgr), fp_(std::move(fp)), paths_(std::move(paths)) {}

PathLockManager::Guard::Guard(Guard&& other) noexcept
    : mgr_(other.mgr_),
      fp_(std::move(other.fp_)),
      paths_(std::move(other.paths_)) {
    other.mgr_ = nullptr;
}

PathLockManager::Guard& PathLockManager::Guard::operator=(Guard&& other) noexcept {
    if (this != &other) {
        release();
        mgr_ = other.mgr_;
        fp_ = std::move(other.fp_);
        paths_ = std::move(other.paths_);
        other.mgr_ = nullptr;
    }
    return *this;
}

PathLockManager::Guard::~Guard() {
    release();
}

void PathLockManager::Guard::release() {
    if (!mgr_) return;
    mgr_->unlock_paths(fp_, paths_);
    mgr_ = nullptr;
}

/*
paths_conflict()
----------------
Two logical paths conflict if one is the same as, parent of, or child of
the other. Prefix comparison must honor "/" as a segment separator so that:
- "docs" conflicts with "docs/a.txt"
- "docs" does NOT conflict with "docs2"
*/
bool PathLockManager::paths_conflict(const std::string& a, const std::string& b) {
    if (a == b) return true;
    if (a.size() < b.size() && b.rfind(a + "/", 0) == 0) return true;
    if (b.size() < a.size() && a.rfind(b + "/", 0) == 0) return true;
    return false;
}

/*
canonicalize_paths()
--------------------
Ensures stable ordering and removes duplicates from the caller-provided lock
set. This avoids accidental duplicate holds and makes lock acquisition order
predictable across handlers.
*/
std::vector<std::string> PathLockManager::canonicalize_paths(std::vector<std::string> paths) {
    std::sort(paths.begin(), paths.end());
    paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
    return paths;
}

/*
lock_paths()
------------
Acquire an exclusive lock set for one user's logical paths.

Behavior:
- blocks until none of the requested paths conflict with currently-held paths
  for the same fingerprint
- then records all requested paths as held
- returns an RAII Guard that will release them automatically

Important:
- requests for different fingerprints never conflict
- requests for the same fingerprint do conflict on equal / ancestor / descendant paths
- unrelated sibling paths may proceed concurrently
*/
PathLockManager::Guard PathLockManager::lock_paths(const std::string& fp,
                                                   std::vector<std::string> paths) {
    paths = canonicalize_paths(std::move(paths));

    std::unique_lock<std::mutex> lk(mu_);
    cv_.wait(lk, [&]() {
        for (const auto& want : paths) {
            for (const auto& e : held_) {
                if (e.fp != fp) continue;
                if (paths_conflict(want, e.path)) return false;
            }
        }
        return true;
    });

    for (const auto& p : paths) {
        held_.push_back(Entry{fp, p, 1});
    }

    return Guard(this, fp, std::move(paths));
}

/*
unlock_paths()
--------------
Release a previously-acquired lock set and wake waiters.

Current implementation removes one matching held_ entry per requested path.
That matches lock_paths(), which inserts one Entry per canonicalized path.

notify_all() is used instead of notify_one() because multiple waiters may be
blocked on different non-overlapping path sets; waking all lets eligible ones
compete to proceed.
*/
void PathLockManager::unlock_paths(const std::string& fp,
                                   const std::vector<std::string>& paths) {
    std::lock_guard<std::mutex> lk(mu_);

    for (const auto& p : paths) {
        auto it = std::find_if(held_.begin(), held_.end(), [&](const Entry& e) {
            return e.fp == fp && e.path == p;
        });
        if (it != held_.end()) {
            held_.erase(it);
        }
    }

    cv_.notify_all();
}

} // namespace pqnas