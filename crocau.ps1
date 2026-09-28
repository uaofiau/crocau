\xef\xbb\xbf# crocau - портабл-оболочка для croc (Windows 7+, PowerShell 2.0+).
# Две вкладки: отправить / получить (файлы, папки, текст) со своим паролем.
param([switch]$SelfTest, [string]$CrocPath = "")

$ErrorActionPreference = "Stop"
$script:AppDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:IniPath = Join-Path $script:AppDir "crocau.ini"
$script:ConfigDir = Join-Path $script:AppDir "croc-config"
if ($CrocPath) { $script:CrocExe = $CrocPath } else { $script:CrocExe = Join-Path $script:AppDir "croc.exe" }

# ---------- C#-помощник (синтаксис C# 2.0 - для PowerShell 2.0 на Win7) ----------
$csharp = @"
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

public class CrocRunner
{
    Process proc;
    Thread t1;
    Thread t2;
    bool drained = false;
    StringBuilder outBuf = new StringBuilder();
    StringBuilder errBuf = new StringBuilder();
    object sync = new object();
    public string StartError = "";

    class Pump
    {
        StreamReader r; StringBuilder b; object l;
        public Pump(StreamReader r, StringBuilder b, object l) { this.r = r; this.b = b; this.l = l; }
        public void Run()
        {
            char[] buf = new char[1024];
            try
            {
                while (true)
                {
                    int n = r.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    lock (l) { b.Append(buf, 0, n); }
                }
            }
            catch (Exception) { }
        }
    }

    // Экранирование аргумента по правилам CommandLineToArgvW (так же разбирает Go).
    public static string Quote(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) return arg;
        StringBuilder sb = new StringBuilder();
        sb.Append('"');
        int i = 0;
        while (true)
        {
            int bs = 0;
            while (i < arg.Length && arg[i] == '\\') { i++; bs++; }
            if (i == arg.Length) { sb.Append('\\', bs * 2); break; }
            else if (arg[i] == '"') { sb.Append('\\', bs * 2 + 1); sb.Append('"'); }
            else { sb.Append('\\', bs); sb.Append(arg[i]); }
            i++;
        }
        sb.Append('"');
        return sb.ToString();
    }

    public bool Start(string exe, string[] args, string workDir, string[] envPairs)
    {
        try
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < args.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(Quote(args[i]));
            }
            ProcessStartInfo psi = new ProcessStartInfo(exe, sb.ToString());
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.RedirectStandardInput = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;
            if (workDir != null && workDir.Length > 0) psi.WorkingDirectory = workDir;
            for (int i = 0; i + 1 < envPairs.Length; i += 2) psi.EnvironmentVariables[envPairs[i]] = envPairs[i + 1];
            proc = Process.Start(psi);
            t1 = new Thread(new ThreadStart(new Pump(proc.StandardOutput, outBuf, sync).Run));
            t2 = new Thread(new ThreadStart(new Pump(proc.StandardError, errBuf, sync).Run));
            t1.IsBackground = true; t2.IsBackground = true;
            t1.Start(); t2.Start();
            return true;
        }
        catch (Exception ex) { StartError = ex.Message; return false; }
    }

    public bool Running
    {
        get
        {
            if (proc == null) return false;
            if (!proc.HasExited) return true;
            if (!drained) { t1.Join(1500); t2.Join(1500); drained = true; }
            return false;
        }
    }

    public int ExitCode { get { return proc == null ? -1 : proc.ExitCode; } }
    public string Out { get { lock (sync) { return outBuf.ToString(); } } }
    public string Err { get { lock (sync) { return errBuf.ToString(); } } }

    public void Kill()
    {
        try { if (proc != null && !proc.HasExited) proc.Kill(); } catch (Exception) { }
    }
}
"@
Add-Type -TypeDefinition $csharp

# ---------- Настройки ----------
function Load-Settings {
    $s = @{ Relay = ''; RelayPass = ''; Proxy = ''; Extra = ''; OutDir = (Join-Path $script:AppDir 'received') }
    if (Test-Path $script:IniPath) {
        foreach ($line in [IO.File]::ReadAllLines($script:IniPath, [Text.Encoding]::UTF8)) {
            $i = $line.IndexOf('=')
            if ($i -gt 0) {
                $k = $line.Substring(0, $i).Trim()
                if ($s.ContainsKey($k)) { $s[$k] = $line.Substring($i + 1) }
            }
        }
    }
    return $s
}

function Save-Settings($s) {
    $text = ''
    foreach ($k in @('Relay', 'RelayPass', 'Proxy', 'Extra', 'OutDir')) { $text += ($k + '=' + $s[$k] + "`r`n") }
    try { [IO.File]::WriteAllText($script:IniPath, $text, (New-Object Text.UTF8Encoding($false))) } catch { }
}

# ---------- Логика запуска croc ----------
function Get-BaseArgs($s) {
    $a = New-Object System.Collections.ArrayList
    if ($s.Relay.Trim()) { [void]$a.Add('--relay'); [void]$a.Add($s.Relay.Trim()) }
    if ($s.RelayPass.Trim()) { [void]$a.Add('--pass'); [void]$a.Add($s.RelayPass.Trim()) }
    $p = $s.Proxy.Trim()
    if ($p) {
        if ($p -match '^(?i)https?://') { [void]$a.Add('--connect'); [void]$a.Add($p) }
        else { [void]$a.Add('--socks5'); [void]$a.Add($p) }
    }
    [void]$a.Add('--ignore-stdin')
    if ($s.Extra.Trim()) {
        foreach ($x in ($s.Extra.Trim() -split '\s+')) { if ($x) { [void]$a.Add($x) } }
    }
    return ,$a
}

function New-TempWork {
    $d = Join-Path ([IO.Path]::GetTempPath()) ('crocau-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($d)
    return $d
}

function Start-Croc($argList, $work, $secret) {
    if (-not (Test-Path $script:CrocExe)) { throw ("Не найден croc.exe: " + $script:CrocExe) }
    if (-not (Test-Path $script:ConfigDir)) { [void][IO.Directory]::CreateDirectory($script:ConfigDir) }
    $envPairs = @('CROC_CONFIG_DIR', $script:ConfigDir)
    if ($secret) { $envPairs += @('CROC_SECRET', $secret) }
    $r = New-Object CrocRunner
    $ok = $r.Start($script:CrocExe, [string[]]($argList.ToArray()), $work, [string[]]$envPairs)
    if (-not $ok) { throw ("Не удалось запустить croc: " + $r.StartError) }
    return $r
}

function Start-Send($s, $password, $items, $text) {
    $a = Get-BaseArgs $s
    [void]$a.Add('send')
    if ($text -ne $null -and $text.Length -gt 0) {
        [void]$a.Add('--text'); [void]$a.Add($text)
    } else {
        foreach ($i in $items) { [void]$a.Add([string]$i) }
    }
    $work = New-TempWork
    $r = Start-Croc $a $work $password
    return @{ Runner = $r; Work = $work }
}

function Start-Receive($s, $password, $outDir) {
    $a = Get-BaseArgs $s
    [void]$a.Add('--yes'); [void]$a.Add('--overwrite')
    [void]$a.Add('--out'); [void]$a.Add($outDir)
    if (-not (Test-Path $outDir)) { [void][IO.Directory]::CreateDirectory($outDir) }
    $work = New-TempWork
    $r = Start-Croc $a $work $password
    return @{ Runner = $r; Work = $work }
}

function Format-Log([string]$raw) {
    if (-not $raw) { return '' }
    $esc = [string][char]27
    $raw = [regex]::Replace($raw, ($esc + '\[[0-9;?]*[A-Za-z]'), '')
    $raw = $raw.Replace("`r`n", "`n")
    $out = New-Object System.Collections.ArrayList
    foreach ($line in $raw.Split("`n")) {
        $l = $line.TrimEnd("`r")
        $i = $l.LastIndexOf("`r")
        if ($i -ge 0) { $l = $l.Substring($i + 1) }
        [void]$out.Add($l)
    }
    while ($out.Count -gt 200) { $out.RemoveAt(0) }
    return ([string]::Join("`r`n", [string[]]$out.ToArray()))
}

function New-Password {
    $chars = 'abcdefghjkmnpqrstuvwxyz23456789'
    $rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
    $b = New-Object byte[] 12
    $rng.GetBytes($b)
    $s = ''
    for ($i = 0; $i -lt 12; $i++) {
        if ($i -gt 0 -and ($i % 4) -eq 0) { $s += '-' }
        $s += $chars[$b[$i] % $chars.Length]
    }
    return $s
}

function Remove-Quiet($path) {
    try { if ($path -and (Test-Path $path)) { Remove-Item -Recurse -Force $path } } catch { }
}

# ---------- Самотест (для CI): relay + отправка/получение текста и файлов ----------
if ($SelfTest) {
    $fail = 0
    $relay = $null
    try {
        $relay = Start-Croc (New-Object System.Collections.ArrayList(, @('relay', '--port', '19009', '--ports', '19009,19010,19011,19012,19013'))) $null $null
        Start-Sleep -Seconds 2
        $s = @{ Relay = '127.0.0.1:19009'; RelayPass = ''; Proxy = ''; Extra = ''; OutDir = '' }

        function Wait-Runner($r, $sec) {
            $t0 = Get-Date
            while ($r.Running) {
                Start-Sleep -Milliseconds 200
                if (((Get-Date) - $t0).TotalSeconds -gt $sec) { $r.Kill(); return $false }
            }
            return $true
        }

        # 1) текст со спецсимволами
        $txt = "Привет, мир!`r`nСтрока 2 `"кавычки`" & % ^ \ \\`" конец"
        $pw = 'test-pass-' + (New-Password)
        $snd = Start-Send $s $pw $null $txt
        Start-Sleep -Seconds 1
        $rcv = Start-Receive $s $pw (New-TempWork)
        $ok1 = (Wait-Runner $rcv.Runner 60)
        [void](Wait-Runner $snd.Runner 30)
        if ($ok1 -and $rcv.Runner.ExitCode -eq 0 -and $rcv.Runner.Out -eq $txt) { Write-Host "TEXT: OK" }
        else { $fail++; Write-Host "TEXT: FAIL"; Write-Host ("OUT=[" + $rcv.Runner.Out + "]"); Write-Host (Format-Log $rcv.Runner.Err); Write-Host (Format-Log $snd.Runner.Err) }

        # 2) файл + папка
        $src = New-TempWork
        $f1 = Join-Path $src 'файл один.bin'
        $bytes = New-Object byte[] 1048576
        (New-Object Random).NextBytes($bytes)
        [IO.File]::WriteAllBytes($f1, $bytes)
        $dir = Join-Path $src 'папка'
        [void][IO.Directory]::CreateDirectory((Join-Path $dir 'sub'))
        [IO.File]::WriteAllText((Join-Path $dir 'sub\a.txt'), 'hello', (New-Object Text.UTF8Encoding($false)))
        $dst = New-TempWork
        $pw2 = 'file-pass-' + (New-Password)
        $snd2 = Start-Send $s $pw2 @($f1, $dir) $null
        Start-Sleep -Seconds 1
        $rcv2 = Start-Receive $s $pw2 $dst
        $ok2 = (Wait-Runner $rcv2.Runner 90)
        [void](Wait-Runner $snd2.Runner 30)
        $g1 = Join-Path $dst 'файл один.bin'
        $g2 = Join-Path $dst 'папка\sub\a.txt'
        $same = $false
        if ((Test-Path $g1) -and (Test-Path $g2)) {
            $b2 = [IO.File]::ReadAllBytes($g1)
            $same = ($b2.Length -eq $bytes.Length)
            if ($same) { for ($i = 0; $i -lt $bytes.Length; $i++) { if ($b2[$i] -ne $bytes[$i]) { $same = $false; break } } }
            if ([IO.File]::ReadAllText($g2) -ne 'hello') { $same = $false }
        }
        if ($ok2 -and $same) { Write-Host "FILES: OK" }
        else { $fail++; Write-Host "FILES: FAIL"; Write-Host (Format-Log $rcv2.Runner.Err); Write-Host (Format-Log $snd2.Runner.Err) }
    } catch {
        $fail++
        Write-Host ("SELFTEST EXCEPTION: " + $_)
    }
    if ($relay) { $relay.Kill() }
    if ($fail -eq 0) { Write-Host "SELFTEST PASSED"; exit 0 } else { Write-Host "SELFTEST FAILED"; exit 1 }
}

# ---------- GUI ----------
if ([Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    $me = $MyInvocation.MyCommand.Path
    Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-WindowStyle', 'Hidden', '-File', ('"' + $me + '"'))
    exit
}

[void][Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
[void][Reflection.Assembly]::LoadWithPartialName('System.Drawing')
[System.Windows.Forms.Application]::EnableVisualStyles()

function New-Ctl($type, $x, $y, $w, $h, $text) {
    $c = New-Object $type
    $c.Location = New-Object Drawing.Point($x, $y)
    $c.Size = New-Object Drawing.Size($w, $h)
    if ($text -ne $null) { $c.Text = $text }
    return $c
}

try {
    $S = Load-Settings
    $script:Runner = $null
    $script:Work = $null
    $script:Mode = ''

    $form = New-Object Windows.Forms.Form
    $form.Text = 'crocau - передача файлов, папок и текста'
    $form.ClientSize = New-Object Drawing.Size(720, 626)
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = New-Object Drawing.Size(600, 560)
    $form.Font = New-Object Drawing.Font('Segoe UI', 9)

    $tabs = New-Ctl 'Windows.Forms.TabControl' 8 8 704 340 $null
    $tabs.Anchor = 'Top,Left,Right'
    $tpSend = New-Object Windows.Forms.TabPage; $tpSend.Text = 'Отправить'
    $tpRecv = New-Object Windows.Forms.TabPage; $tpRecv.Text = 'Получить'
    $tpSet = New-Object Windows.Forms.TabPage;  $tpSet.Text = 'Настройки'
    $tabs.TabPages.Add($tpSend); $tabs.TabPages.Add($tpRecv); $tabs.TabPages.Add($tpSet)

    # --- Отправить ---
    $rbSFiles = New-Ctl 'Windows.Forms.RadioButton' 10 10 150 22 'Файлы и папки'
    $rbSFiles.Checked = $true
    $rbSText = New-Ctl 'Windows.Forms.RadioButton' 170 10 120 22 'Текст'
    $lst = New-Ctl 'Windows.Forms.ListBox' 10 38 560 150 $null
    $lst.SelectionMode = 'MultiExtended'; $lst.HorizontalScrollBar = $true; $lst.AllowDrop = $true
    $lst.Anchor = 'Top,Left,Right'
    $btnAddF = New-Ctl 'Windows.Forms.Button' 580 38 110 26 'Файлы...'
    $btnAddD = New-Ctl 'Windows.Forms.Button' 580 68 110 26 'Папка...'
    $btnDel = New-Ctl 'Windows.Forms.Button' 580 98 110 26 'Убрать'
    $btnClr = New-Ctl 'Windows.Forms.Button' 580 128 110 26 'Очистить'
    foreach ($b in @($btnAddF, $btnAddD, $btnDel, $btnClr)) { $b.Anchor = 'Top,Right' }
    $txtSend = New-Ctl 'Windows.Forms.TextBox' 10 38 560 150 $null
    $txtSend.Multiline = $true; $txtSend.ScrollBars = 'Vertical'; $txtSend.AcceptsReturn = $true
    $txtSend.Anchor = 'Top,Left,Right'; $txtSend.Visible = $false
    $btnPaste = New-Ctl 'Windows.Forms.Button' 580 38 110 26 'Из буфера'
    $btnPaste.Anchor = 'Top,Right'; $btnPaste.Visible = $false
    $lblSP = New-Ctl 'Windows.Forms.Label' 10 200 400 20 'Пароль передачи (не короче 6 символов):'
    $txtSP = New-Ctl 'Windows.Forms.TextBox' 10 222 300 24 $null
    $btnGen = New-Ctl 'Windows.Forms.Button' 320 220 110 26 'Случайный'
    $btnSend = New-Ctl 'Windows.Forms.Button' 10 262 150 34 'Отправить'
    $btnSend.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
    $btnStopS = New-Ctl 'Windows.Forms.Button' 170 262 100 34 'Стоп'
    $btnStopS.Enabled = $false
    $tpSend.Controls.AddRange(@($rbSFiles, $rbSText, $lst, $btnAddF, $btnAddD, $btnDel, $btnClr, $txtSend, $btnPaste, $lblSP, $txtSP, $btnGen, $btnSend, $btnStopS))

    # --- Получить ---
    $lblRP = New-Ctl 'Windows.Forms.Label' 10 10 500 20 'Пароль (тот, что задал отправитель):'
    $txtRP = New-Ctl 'Windows.Forms.TextBox' 10 32 300 24 $null
    $rbRFiles = New-Ctl 'Windows.Forms.RadioButton' 10 66 150 22 'Файлы и папки'
    $rbRFiles.Checked = $true
    $rbRText = New-Ctl 'Windows.Forms.RadioButton' 170 66 120 22 'Текст'
    $lblOut = New-Ctl 'Windows.Forms.Label' 10 96 300 20 'Папка для сохранения:'
    $txtOut = New-Ctl 'Windows.Forms.TextBox' 10 118 560 24 $S.OutDir
    $txtOut.Anchor = 'Top,Left,Right'
    $btnBrowse = New-Ctl 'Windows.Forms.Button' 580 116 110 26 'Обзор...'
    $btnBrowse.Anchor = 'Top,Right'
    $lblRT = New-Ctl 'Windows.Forms.Label' 10 150 300 20 'Полученный текст:'
    $txtRT = New-Ctl 'Windows.Forms.TextBox' 10 172 560 90 $null
    $txtRT.Multiline = $true; $txtRT.ScrollBars = 'Vertical'; $txtRT.ReadOnly = $true
    $txtRT.Anchor = 'Top,Left,Right'
    $btnCopyT = New-Ctl 'Windows.Forms.Button' 580 172 110 26 'Копировать'
    $btnCopyT.Anchor = 'Top,Right'
    $btnRecv = New-Ctl 'Windows.Forms.Button' 10 272 150 34 'Получить'
    $btnRecv.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
    $btnStopR = New-Ctl 'Windows.Forms.Button' 170 272 100 34 'Стоп'
    $btnStopR.Enabled = $false
    $tpRecv.Controls.AddRange(@($lblRP, $txtRP, $rbRFiles, $rbRText, $lblOut, $txtOut, $btnBrowse, $lblRT, $txtRT, $btnCopyT, $btnRecv, $btnStopR))

    # --- Настройки ---
    $l1 = New-Ctl 'Windows.Forms.Label' 10 10 680 20 'Адрес relay (host:порт). Пусто = публичный relay croc:'
    $txtRelay = New-Ctl 'Windows.Forms.TextBox' 10 32 420 24 $S.Relay
    $l2 = New-Ctl 'Windows.Forms.Label' 10 66 680 20 'Пароль relay (пусто = по умолчанию):'
    $txtRelayPass = New-Ctl 'Windows.Forms.TextBox' 10 88 420 24 $S.RelayPass
    $l3 = New-Ctl 'Windows.Forms.Label' 10 122 680 20 'Прокси: socks5://host:port или http://host:port (пусто = без прокси):'
    $txtProxy = New-Ctl 'Windows.Forms.TextBox' 10 144 420 24 $S.Proxy
    $l4 = New-Ctl 'Windows.Forms.Label' 10 178 680 20 'Доп. общие ключи croc через пробел (например: --internal-dns --no-multi):'
    $txtExtra = New-Ctl 'Windows.Forms.TextBox' 10 200 420 24 $S.Extra
    $l5 = New-Ctl 'Windows.Forms.Label' 10 240 680 40 'Настройки хранятся в crocau.ini рядом с программой. Пароль передачи нигде не сохраняется.'
    $tpSet.Controls.AddRange(@($l1, $txtRelay, $l2, $txtRelayPass, $l3, $txtProxy, $l4, $txtExtra, $l5))

    # --- Журнал ---
    $lblLog = New-Ctl 'Windows.Forms.Label' 8 354 704 18 'Ход передачи:'
    $lblLog.Anchor = 'Top,Left,Right'
    $log = New-Ctl 'Windows.Forms.TextBox' 8 374 704 210 $null
    $log.Multiline = $true; $log.ReadOnly = $true; $log.ScrollBars = 'Vertical'
    $log.Font = New-Object Drawing.Font('Consolas', 9)
    $log.Anchor = 'Top,Bottom,Left,Right'
    $btnCopyLog = New-Ctl 'Windows.Forms.Button' 8 592 160 26 'Копировать журнал'
    $btnCopyLog.Anchor = 'Bottom,Left'

    $form.Controls.AddRange(@($tabs, $lblLog, $log, $btnCopyLog))

    $timer = New-Object Windows.Forms.Timer
    $timer.Interval = 300

    function Get-CurrentSettings {
        return @{ Relay = $txtRelay.Text; RelayPass = $txtRelayPass.Text; Proxy = $txtProxy.Text; Extra = $txtExtra.Text; OutDir = $txtOut.Text }
    }

    function Set-Busy($busy) {
        $btnSend.Enabled = -not $busy; $btnRecv.Enabled = -not $busy
        $btnStopS.Enabled = $busy; $btnStopR.Enabled = $busy
    }

    function Add-Paths($paths) {
        foreach ($p in $paths) {
            if (-not $lst.Items.Contains($p)) { [void]$lst.Items.Add($p) }
        }
    }

    function Show-Error($msg) {
        [void][Windows.Forms.MessageBox]::Show($msg, 'crocau', 'OK', 'Warning')
    }

    $rbSFiles.Add_CheckedChanged({
        $isFiles = $rbSFiles.Checked
        $lst.Visible = $isFiles; $btnAddF.Visible = $isFiles; $btnAddD.Visible = $isFiles
        $btnDel.Visible = $isFiles; $btnClr.Visible = $isFiles
        $txtSend.Visible = -not $isFiles; $btnPaste.Visible = -not $isFiles
    })
    $rbRText.Add_CheckedChanged({
        $isText = $rbRText.Checked
        $lblOut.Enabled = -not $isText; $txtOut.Enabled = -not $isText; $btnBrowse.Enabled = -not $isText
    })

    $lst.Add_DragEnter({ param($s, $e)
        if ($e.Data.GetDataPresent([Windows.Forms.DataFormats]::FileDrop)) { $e.Effect = [Windows.Forms.DragDropEffects]::Copy }
    })
    $lst.Add_DragDrop({ param($s, $e)
        Add-Paths ($e.Data.GetData([Windows.Forms.DataFormats]::FileDrop))
    })

    $btnAddF.Add_Click({
        $d = New-Object Windows.Forms.OpenFileDialog
        $d.Multiselect = $true
        if ($d.ShowDialog() -eq 'OK') { Add-Paths $d.FileNames }
    })
    $btnAddD.Add_Click({
        $d = New-Object Windows.Forms.FolderBrowserDialog
        if ($d.ShowDialog() -eq 'OK') { Add-Paths @($d.SelectedPath) }
    })
    $btnDel.Add_Click({
        $sel = @(); foreach ($i in $lst.SelectedItems) { $sel += $i }
        foreach ($i in $sel) { $lst.Items.Remove($i) }
    })
    $btnClr.Add_Click({ $lst.Items.Clear() })
    $btnPaste.Add_Click({
        if ([Windows.Forms.Clipboard]::ContainsText()) { $txtSend.Text = [Windows.Forms.Clipboard]::GetText() }
    })
    $btnGen.Add_Click({ $txtSP.Text = (New-Password) })
    $btnBrowse.Add_Click({
        $d = New-Object Windows.Forms.FolderBrowserDialog
        if ($d.ShowDialog() -eq 'OK') { $txtOut.Text = $d.SelectedPath }
    })
    $btnCopyT.Add_Click({ if ($txtRT.Text.Length -gt 0) { [Windows.Forms.Clipboard]::SetText($txtRT.Text) } })
    $btnCopyLog.Add_Click({ if ($log.Text.Length -gt 0) { [Windows.Forms.Clipboard]::SetText($log.Text) } })

    $btnSend.Add_Click({
        $pw = $txtSP.Text
        if ($pw.Length -lt 6) { Show-Error 'Пароль должен быть не короче 6 символов.'; return }
        $text = $null; $items = @()
        if ($rbSText.Checked) {
            $text = $txtSend.Text
            if ($text.Length -eq 0) { Show-Error 'Введите текст для отправки.'; return }
        } else {
            foreach ($i in $lst.Items) { $items += [string]$i }
            if ($items.Count -eq 0) { Show-Error 'Добавьте файлы или папки (можно перетащить мышью).'; return }
        }
        $set = Get-CurrentSettings
        Save-Settings $set
        try {
            $res = Start-Send $set $pw $items $text
        } catch { Show-Error ([string]$_); return }
        $script:Runner = $res.Runner; $script:Work = $res.Work; $script:Mode = 'send'
        $log.Text = 'Отправка запущена. Передайте получателю пароль и дождитесь подключения...'
        Set-Busy $true
        $timer.Start()
    })

    $btnRecv.Add_Click({
        $pw = $txtRP.Text
        if ($pw.Length -lt 6) { Show-Error 'Пароль должен быть не короче 6 символов.'; return }
        $set = Get-CurrentSettings
        $isText = $rbRText.Checked
        $script:RecvDir = $null
        if ($isText) {
            $out = New-TempWork
            $script:RecvDir = $out
        } else {
            $out = $txtOut.Text.Trim()
            if (-not $out) { Show-Error 'Укажите папку для сохранения.'; return }
        }
        Save-Settings $set
        $txtRT.Text = ''
        try {
            $res = Start-Receive $set $pw $out
        } catch { Show-Error ([string]$_); return }
        $script:Runner = $res.Runner; $script:Work = $res.Work
        if ($isText) { $script:Mode = 'recvtext' } else { $script:Mode = 'recv' }
        $script:OutShown = $out
        $log.Text = 'Ожидание отправителя...'
        Set-Busy $true
        $timer.Start()
    })

    $stopHandler = {
        if ($script:Runner) { $script:Runner.Kill() }
    }
    $btnStopS.Add_Click($stopHandler)
    $btnStopR.Add_Click($stopHandler)

    $timer.Add_Tick({
        if ($script:Runner -eq $null) { $timer.Stop(); return }
        $running = $script:Runner.Running
        $txt = Format-Log $script:Runner.Err
        if ($txt -and $txt -ne $log.Text) {
            $log.Text = $txt
            $log.SelectionStart = $log.Text.Length
            $log.ScrollToCaret()
        }
        if (-not $running) {
            $timer.Stop()
            $code = $script:Runner.ExitCode
            $outText = $script:Runner.Out
            $extra = ''
            if ($code -eq 0) {
                $extra = "`r`n=== Готово ==="
                if ($script:Mode -eq 'recvtext') {
                    $txtRT.Text = $outText.Replace("`r`n", "`n").Replace("`n", "`r`n")
                } elseif ($script:Mode -eq 'recv') {
                    $extra += "`r`nСохранено в: " + $script:OutShown
                }
            } else {
                $extra = "`r`n=== Остановлено или ошибка (код " + $code + ") ==="
            }
            $log.Text = $log.Text + $extra
            $log.SelectionStart = $log.Text.Length
            $log.ScrollToCaret()
            Remove-Quiet $script:Work
            if ($script:RecvDir) { Remove-Quiet $script:RecvDir; $script:RecvDir = $null }
            $script:Runner = $null
            Set-Busy $false
        }
    })

    $form.Add_FormClosing({
        Save-Settings (Get-CurrentSettings)
        if ($script:Runner) { $script:Runner.Kill() }
    })

    [void]$form.ShowDialog()
}
catch {
    $msg = "crocau: ошибка`r`n" + [string]$_ + "`r`n" + $_.ScriptStackTrace
    try { [IO.File]::WriteAllText((Join-Path $script:AppDir 'crocau-error.log'), $msg) } catch { }
    try { [void][Windows.Forms.MessageBox]::Show($msg, 'crocau') } catch { }
    exit 1
}
