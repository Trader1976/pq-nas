#!/usr/bin/env bash
set -u
# "Run : BASE="$BASE" COOKIE="$COOKIE" ./tools/fs_regression.sh"
: "${BASE:?missing BASE}"
: "${COOKIE:?missing COOKIE}"

PASS_COUNT=0
FAIL_COUNT=0
TEST_NS="reg_$(date +%s)"

tp() {
  printf '%s/%s' "$TEST_NS" "$1"
}

req() {
  local method="$1"
  local url="$2"
  local body="${3-}"

  if [[ -n "$body" ]]; then
    curl -sS -X "$method" "$url" \
      -H "Cookie: $COOKIE" \
      --data-binary "$body"
  else
    curl -sS -X "$method" "$url" \
      -H "Cookie: $COOKIE"
  fi
}

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf 'PASS: %s\n' "$1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  printf 'FAIL: %s\n' "$1"
  if [[ $# -ge 2 ]]; then
    printf '  detail: %s\n' "$2"
  fi
}

json_field() {
  local json="$1"
  local key="$2"
  printf '%s' "$json" | jq -r --arg k "$key" '
    if type == "object" and has($k) then .[$k] else empty end
  ' 2>/dev/null
}

expect_error() {
  local name="$1"
  local json="$2"
  local want_error="$3"

  if printf '%s' "$json" | jq -e --arg e "$want_error" '
      type == "object" and .ok == false and .error == $e
    ' >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name" "expected error=$want_error, got: $json"
  fi
}

expect_ok() {
  local name="$1"
  local json="$2"

  if printf '%s' "$json" | jq -e '
      type == "object" and .ok == true
    ' >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name" "expected ok=true, got: $json"
  fi
}

expect_list_has_name() {
  local name="$1"
  local json="$2"
  local want="$3"

  if printf '%s' "$json" | jq -e --arg n "$want" '
      any((.items // [])[]; .name == $n)
    ' >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name" "expected list to contain name=$want, got: $json"
  fi
}

expect_list_missing_name() {
  local name="$1"
  local json="$2"
  local want="$3"

  if printf '%s' "$json" | jq -e --arg n "$want" '
      any((.items // [])[]; .name == $n) | not
    ' >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name" "expected list NOT to contain name=$want, got: $json"
  fi
}

cleanup_path() {
  local p="$1"
  req POST "$BASE/api/v4/files/delete?path=$p" >/dev/null 2>&1 || true
}

put_text() {
  local path="$1"
  local text="$2"
  req PUT "$BASE/api/v4/files/put?path=$path" "$text"
}

move_path() {
  local from="$1"
  local to="$2"
  req POST "$BASE/api/v4/files/move?from=$from&to=$to"
}

list_path() {
  local path="$1"
  curl -sS "$BASE/api/v4/files/list?path=$path" -H "Cookie: $COOKIE"
}

stat_path() {
  local path="$1"
  req POST "$BASE/api/v4/files/stat?path=$path"
}

expect_field_eq() {
  local name="$1"
  local json="$2"
  local key="$3"
  local want="$4"

  if printf '%s' "$json" | jq -e --arg k "$key" --arg w "$want" '
      type == "object" and (.[$k] | tostring) == $w
    ' >/dev/null 2>&1; then
    pass "$name"
  else
    fail "$name" "expected $key=$want, got: $json"
  fi
}

echo "== PQ-NAS filesystem regression =="
echo "Namespace: $TEST_NS"

# --------------------------------------------------------------------
# Cleanup test namespace
# --------------------------------------------------------------------
cleanup_path "$TEST_NS"

# --------------------------------------------------------------------
# 1. Reserved path rejection
# --------------------------------------------------------------------
resp="$(put_text ".pqnas/x" "x")"
expect_error "reserved path rejected" "$resp" "bad_request"

# --------------------------------------------------------------------
# 2. Ancestor file conflict on PUT
# a exists as file, so a/b.txt must fail
# --------------------------------------------------------------------
resp="$(put_text "$(tp a)" "rootfile")"
expect_ok "put file a" "$resp"

resp="$(put_text "$(tp a)/b.txt" "child")"
expect_error "put child under file rejected" "$resp" "path_conflict"

# --------------------------------------------------------------------
# 3. Descendant dir conflict on PUT
# docs/a.txt exists, so PUT docs must fail
# --------------------------------------------------------------------
cleanup_path "$(tp docs)"

resp="$(put_text "$(tp docs)/a.txt" "A")"
expect_ok "put docs/a.txt" "$resp"

resp="$(put_text "$(tp docs)" "ROOT")"
expect_error "put file over logical dir rejected" "$resp" "path_conflict"

# --------------------------------------------------------------------
# 4. File move into file-parent rejected
# parentfile is file, so child.txt -> parentfile/sub.txt must fail
# --------------------------------------------------------------------
cleanup_path "$(tp parentfile)"
cleanup_path "$(tp child.txt)"

resp="$(put_text "$(tp parentfile)" "P")"
expect_ok "put parentfile" "$resp"

resp="$(put_text "$(tp child.txt)" "C")"
expect_ok "put child.txt" "$resp"

resp="$(move_path "$(tp child.txt)" "$(tp parentfile)/sub.txt")"
expect_error "move file under file-parent rejected" "$resp" "path_conflict"

# --------------------------------------------------------------------
# 5. Dir move into file-parent rejected
# topfile is file, so docs -> topfile/subdir must fail
# --------------------------------------------------------------------
cleanup_path "$(tp docs)"
cleanup_path "$(tp topfile)"

resp="$(put_text "$(tp topfile)" "T")"
expect_ok "put topfile" "$resp"

resp="$(put_text "$(tp docs)/a.txt" "A")"
expect_ok "put docs/a.txt for dir-move test" "$resp"

resp="$(move_path "$(tp docs)" "$(tp topfile)/subdir")"
expect_error "move dir under file-parent rejected" "$resp" "path_conflict"

# --------------------------------------------------------------------
# 6. Same-path move rejected
# --------------------------------------------------------------------
resp="$(move_path "$(tp docs)" "$(tp docs)")"
expect_error "same-path move rejected" "$resp" "bad_request"

# --------------------------------------------------------------------
# 7. Dir into self rejected
# docs -> docs/sub/inner
# --------------------------------------------------------------------
resp="$(move_path "$(tp docs)" "$(tp docs)/sub/inner")"
expect_error "dir into itself rejected" "$resp" "bad_request"

# --------------------------------------------------------------------
# 8. Clean dir move to fresh destination
# docs -> moved/docs
# --------------------------------------------------------------------
cleanup_path "$(tp docs)"
cleanup_path "$(tp moved)"

resp="$(put_text "$(tp docs)/a.txt" "A")"
expect_ok "put docs/a.txt for clean move" "$resp"

resp="$(put_text "$(tp docs)/sub/b.txt" "B")"
expect_ok "put docs/sub/b.txt for clean move" "$resp"

resp="$(move_path "$(tp docs)" "$(tp moved)/docs")"
expect_ok "move docs -> moved/docs" "$resp"

resp="$(list_path "$(tp moved)/docs")"
expect_list_has_name "moved/docs contains a.txt" "$resp" "a.txt"
expect_list_has_name "moved/docs contains sub" "$resp" "sub"

resp="$(list_path "$(tp docs)")"
expect_error "old docs path gone after move" "$resp" "not_found"

# --------------------------------------------------------------------
# 9. Delete moved subtree
# --------------------------------------------------------------------
resp="$(req POST "$BASE/api/v4/files/delete?path=$(tp moved)")"
expect_ok "delete moved subtree" "$resp"

resp="$(list_path "$(tp moved)")"
expect_error "moved gone after delete" "$resp" "not_found"

# --------------------------------------------------------------------
# 10. Move into existing destination rejected cleanly
# docs exists, archive/docs exists
# --------------------------------------------------------------------
cleanup_path "$(tp docs)"
cleanup_path "$(tp archive)"

resp="$(put_text "$(tp docs)/a.txt" "A")"
expect_ok "put docs/a.txt for existing-dest move" "$resp"

resp="$(put_text "$(tp archive)/docs/existing.txt" "X")"
expect_ok "put archive/docs/existing.txt" "$resp"

resp="$(move_path "$(tp docs)" "$(tp archive)/docs")"
expect_error "move into existing destination rejected" "$resp" "dest_exists"

resp="$(list_path "$(tp docs)")"
expect_list_has_name "docs still contains a.txt after rejected move" "$resp" "a.txt"

resp="$(list_path "$(tp archive)/docs")"
expect_list_has_name "archive/docs still contains existing.txt after rejected move" "$resp" "existing.txt"

# --------------------------------------------------------------------
# 11. File move onto existing file rejected
# --------------------------------------------------------------------
cleanup_path "$(tp fileA.txt)"
cleanup_path "$(tp fileB.txt)"

resp="$(put_text "$(tp fileA.txt)" "A")"
expect_ok "put fileA.txt" "$resp"

resp="$(put_text "$(tp fileB.txt)" "B")"
expect_ok "put fileB.txt" "$resp"

resp="$(move_path "$(tp fileA.txt)" "$(tp fileB.txt)")"
expect_error "move file onto existing file rejected" "$resp" "dest_exists"

# --------------------------------------------------------------------
# 12. Simple file delete still works
# --------------------------------------------------------------------
cleanup_path "$(tp one.txt)"

resp="$(put_text "$(tp one.txt)" "1")"
expect_ok "put one.txt" "$resp"

resp="$(req POST "$BASE/api/v4/files/delete?path=$(tp one.txt)")"
expect_ok "delete one.txt" "$resp"

resp="$(list_path "$TEST_NS")"
expect_list_missing_name "namespace no longer contains one.txt" "$resp" "one.txt"

# --------------------------------------------------------------------
# 13. Stat works after move
# --------------------------------------------------------------------
cleanup_path "$(tp statdir)"
cleanup_path "$(tp statmoved)"

resp="$(put_text "$(tp statdir)/a.txt" "A")"
expect_ok "put statdir/a.txt" "$resp"

resp="$(put_text "$(tp statdir)/sub/b.txt" "B")"
expect_ok "put statdir/sub/b.txt" "$resp"

resp="$(move_path "$(tp statdir)" "$(tp statmoved)/statdir")"
expect_ok "move statdir -> statmoved/statdir" "$resp"

resp="$(stat_path "$(tp statmoved)/statdir")"
expect_ok "stat moved dir ok" "$resp"
expect_field_eq "stat moved dir type=dir" "$resp" "type" "dir"
expect_field_eq "stat moved dir exists=true" "$resp" "exists" "true"

resp="$(stat_path "$(tp statmoved)/statdir/a.txt")"
expect_ok "stat moved file ok" "$resp"
expect_field_eq "stat moved file type=file" "$resp" "type" "file"
expect_field_eq "stat moved file exists=true" "$resp" "exists" "true"

# --------------------------------------------------------------------
# 14. Stat on deleted paths returns not_found
# --------------------------------------------------------------------
cleanup_path "$(tp gonefile)"
cleanup_path "$(tp gonedir)"

resp="$(put_text "$(tp gonefile)" "Z")"
expect_ok "put gonefile" "$resp"

resp="$(put_text "$(tp gonedir)/x.txt" "X")"
expect_ok "put gonedir/x.txt" "$resp"

resp="$(req POST "$BASE/api/v4/files/delete?path=$(tp gonefile)")"
expect_ok "delete gonefile" "$resp"

resp="$(req POST "$BASE/api/v4/files/delete?path=$(tp gonedir)")"
expect_ok "delete gonedir" "$resp"

resp="$(stat_path "$(tp gonefile)")"
expect_error "stat deleted file returns not_found" "$resp" "not_found"

resp="$(stat_path "$(tp gonedir)")"
expect_error "stat deleted dir returns not_found" "$resp" "not_found"

# --------------------------------------------------------------------
# 15. PUT overwrite existing file works
# --------------------------------------------------------------------
cleanup_path "$(tp overwrite.txt)"

resp="$(put_text "$(tp overwrite.txt)" "OLD")"
expect_ok "put overwrite.txt old" "$resp"

resp="$(put_text "$(tp overwrite.txt)" "NEWER")"
expect_ok "put overwrite.txt overwrite" "$resp"

resp="$(stat_path "$(tp overwrite.txt)")"
expect_ok "stat overwrite.txt ok" "$resp"
expect_field_eq "stat overwrite.txt type=file" "$resp" "type" "file"
expect_field_eq "stat overwrite.txt exists=true" "$resp" "exists" "true"
expect_field_eq "overwrite.txt size updated" "$resp" "bytes" "5"

# --------------------------------------------------------------------
# Final cleanup
# --------------------------------------------------------------------
cleanup_path "$TEST_NS"

resp="$(list_path "")"
expect_list_missing_name "root list no longer contains namespace entry after final cleanup" "$resp" "$TEST_NS"

echo
echo "== Summary =="
echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"

if [[ "$FAIL_COUNT" -ne 0 ]]; then
  exit 1
fi