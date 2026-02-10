package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type Config struct {
	ListenAddr       string
	WGIf             string
	WGConfPath       string
	WGNetCIDR        string
	AllowedLanCIDR   string
	ClientDNS        string
	EndpointPublicIP string

	Udp2RawTcpPort   int
	Udp2RawLocalPort int

	OutputDir       string
	Udp2RawPassword string

	// Windows MTU applied via netsh after tunnel is up.
	// -1 means "not set / disabled"
	ClientMTU int

	// Web UI password (mandatory)
	WebPassword string
}

type App struct {
	Cfg  Config
	Tmpl *template.Template
}

type ClientRow struct {
	Name       string
	HasFolder  bool
	FolderPath string
}

type LastResult struct {
	Name      string
	ClientIP  string
	OutDir    string
	ZipURL    string
	CreatedAt string
}

var lastResult *LastResult

func main() {
	cfg := Config{
		ClientMTU: -1, // default disabled unless -MTU provided
	}

	flag.StringVar(&cfg.ListenAddr, "listen", ":8080", "listen address")
	flag.StringVar(&cfg.WGIf, "wg-if", "wg0", "wireguard interface name")
	flag.StringVar(&cfg.WGConfPath, "wg-conf", "", "wireguard conf path (default /etc/wireguard/<if>.conf)")
	flag.StringVar(&cfg.WGNetCIDR, "wg-net", "10.66.66.0/24", "wireguard subnet CIDR")
	flag.StringVar(&cfg.AllowedLanCIDR, "allowed-lan", "192.168.56.0/24", "AllowedIPs for clients (NO 0.0.0.0/0)")
	flag.StringVar(&cfg.ClientDNS, "dns", "1.1.1.1", "client DNS")
	flag.StringVar(&cfg.EndpointPublicIP, "endpoint-public-ip", "", "server public IP or hostname")
	flag.IntVar(&cfg.Udp2RawTcpPort, "udp2raw-tcp-port", 443, "server tcp port for udp2raw (public)")
	flag.IntVar(&cfg.Udp2RawLocalPort, "udp2raw-local-port", 51820, "client local udp port used by udp2raw; WG Endpoint points here")
	flag.StringVar(&cfg.OutputDir, "out", "/opt/wg-webui/clients", "output directory for generated client bundles")
	flag.StringVar(&cfg.Udp2RawPassword, "udp2raw-pass", "Mongolia2026$", "udp2raw password (fixed)")

	// Only -MTU exists; default disabled.
	flag.IntVar(&cfg.ClientMTU, "MTU", -1, "OPTIONAL: Windows client MTU applied via netsh after tunnel is up (omit to disable)")

	// NEW: mandatory web password
	flag.StringVar(&cfg.WebPassword, "password", "", "MANDATORY: WebUI password (Basic Auth user=admin)")

	flag.Parse()

	if cfg.WGConfPath == "" {
		cfg.WGConfPath = fmt.Sprintf("/etc/wireguard/%s.conf", cfg.WGIf)
	}

	mustRoot()

	if cfg.WebPassword == "" {
		fmt.Println("[!] -password is mandatory (WebUI password). Example: -password \"MyStrongPass\"")
		os.Exit(1)
	}
	if cfg.EndpointPublicIP == "" {
		fmt.Println("[!] -endpoint-public-ip is required (public IP or DNS name).")
		os.Exit(1)
	}
	if _, _, err := net.ParseCIDR(cfg.WGNetCIDR); err != nil {
		die("bad -wg-net: %v", err)
	}
	if _, _, err := net.ParseCIDR(cfg.AllowedLanCIDR); err != nil {
		die("bad -allowed-lan: %v", err)
	}
	if cfg.ClientMTU != -1 && (cfg.ClientMTU < 576 || cfg.ClientMTU > 1500) {
		die("bad -MTU: %d (omit -MTU to disable)", cfg.ClientMTU)
	}

	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		die("mkdir out: %v", err)
	}

	tmpl := template.Must(template.New("index").Parse(indexHTML))
	app := &App{Cfg: cfg, Tmpl: tmpl}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/add", app.handleAdd)
	mux.HandleFunc("/delete", app.handleDelete)
	mux.HandleFunc("/bundle/", app.handleBundleZip)

	// Protect everything with Basic Auth
	protected := app.basicAuthMiddleware(mux)

	fmt.Printf("[+] WebUI listening on %s\n", cfg.ListenAddr)
	fmt.Printf("[+] Output dir: %s\n", cfg.OutputDir)
	fmt.Printf("[+] WebUI auth: Basic (user=admin, password=*** set via -password)\n")
	if cfg.ClientMTU == -1 {
		fmt.Printf("[+] Windows MTU: disabled (no -MTU provided)\n")
	} else {
		fmt.Printf("[+] Windows MTU: %d (enabled)\n", cfg.ClientMTU)
	}

	die("%v", http.ListenAndServe(cfg.ListenAddr, protected))
}

func mustRoot() {
	if os.Geteuid() != 0 {
		fmt.Println("[!] run as root (needs to edit wg config + restart)")
		os.Exit(1)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func (a *App) basicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Basic Auth: user=admin, pass=cfg.WebPassword
		user, pass, ok := r.BasicAuth()
		if !ok || user != "admin" || pass != a.Cfg.WebPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="DodgeVPN"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	confText := ""
	if b, err := os.ReadFile(a.Cfg.WGConfPath); err == nil {
		confText = string(b)
	}

	clients := a.listClients(confText)

	mtuLabel := "disabled"
	if a.Cfg.ClientMTU != -1 {
		mtuLabel = fmt.Sprintf("%d", a.Cfg.ClientMTU)
	}

	_ = a.Tmpl.Execute(w, map[string]any{
		"WGIf":           a.Cfg.WGIf,
		"WGConf":         a.Cfg.WGConfPath,
		"WGNet":          a.Cfg.WGNetCIDR,
		"AllowedLan":     a.Cfg.AllowedLanCIDR,
		"Endpoint":       a.Cfg.EndpointPublicIP,
		"Udp2RawTcpPort": a.Cfg.Udp2RawTcpPort,
		"Udp2RawPass":    a.Cfg.Udp2RawPassword,
		"ClientMTU":      mtuLabel,
		"Last":           lastResult,
		"Clients":        clients,
	})
}

func (a *App) handleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), 400)
		return
	}

	clientName := sanitizeName(r.FormValue("name"))
	if clientName == "" {
		http.Error(w, "missing name", 400)
		return
	}

	confBytes, err := os.ReadFile(a.Cfg.WGConfPath)
	if err != nil {
		http.Error(w, "cannot read wg conf: "+err.Error(), 500)
		return
	}
	confText := string(confBytes)

	// Prevent duplicates (by comment marker)
	if hasClientMarker(confText, clientName) {
		http.Error(w, "client already exists in wg config: "+clientName, 409)
		return
	}

	serverPub, err := getServerPublicKey(a.Cfg.WGIf)
	if err != nil {
		http.Error(w, "cannot get server public key: "+err.Error(), 500)
		return
	}

	nextIP, err := nextClientIP(a.Cfg.WGNetCIDR, confText)
	if err != nil {
		http.Error(w, "cannot allocate ip: "+err.Error(), 500)
		return
	}

	clientPriv, clientPub, err := genWGKeypair()
	if err != nil {
		http.Error(w, "cannot gen keys: "+err.Error(), 500)
		return
	}

	peerBlock := fmt.Sprintf("\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n",
		clientName, clientPub, nextIP.IP.String())

	if err := os.WriteFile(a.Cfg.WGConfPath, []byte(confText+peerBlock), 0600); err != nil {
		http.Error(w, "cannot write wg conf: "+err.Error(), 500)
		return
	}
	if err := restartWG(a.Cfg.WGIf); err != nil {
		http.Error(w, "wg restart failed: "+err.Error(), 500)
		return
	}

	outDir := filepath.Join(a.Cfg.OutputDir, clientName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		http.Error(w, "mkdir client out: "+err.Error(), 500)
		return
	}

	// Endpoint points to local udp2raw on Windows.
	// MTU is NOT in config; if enabled it is applied post-up via netsh.
	clientConf := a.renderClientConf(clientPriv, nextIP.String(), serverPub, "127.0.0.1", a.Cfg.Udp2RawLocalPort)
	clientConfAlt := a.renderClientConf(clientPriv, nextIP.String(), serverPub, "REPLACE_WITH_LOCAL_CLIENT_IP", a.Cfg.Udp2RawLocalPort)

	confPath := filepath.Join(outDir, fmt.Sprintf("%s.conf", clientName))
	confAltPath := filepath.Join(outDir, fmt.Sprintf("%s_alt.conf", clientName))
	_ = os.WriteFile(confPath, []byte(clientConf), 0600)
	_ = os.WriteFile(confAltPath, []byte(clientConfAlt), 0600)

	qrPath := filepath.Join(outDir, fmt.Sprintf("%s.png", clientName))
	if err := makeQRPNG(clientConf, qrPath); err != nil {
		http.Error(w, "qrencode failed: "+err.Error(), 500)
		return
	}

	ps1Path := filepath.Join(outDir, "install_all.ps1")
	readmePath := filepath.Join(outDir, "README_WINDOWS.txt")
	shPath := filepath.Join(outDir, "install_client.sh") // NEW

	ps1 := a.renderWindowsInstallAllPS1(clientName)
	readme := a.renderWindowsReadme(clientName)
	sh := a.renderInstallClientSH(clientName) // NEW

	_ = os.WriteFile(ps1Path, []byte(ps1), 0644)
	_ = os.WriteFile(readmePath, []byte(readme), 0644)
	_ = os.WriteFile(shPath, []byte(sh), 0755)

	zipURL := "/bundle/" + clientName + ".zip"
	lastResult = &LastResult{
		Name:      clientName,
		ClientIP:  nextIP.String(),
		OutDir:    outDir,
		ZipURL:    zipURL,
		CreatedAt: time.Now().Format(time.RFC3339),
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form: "+err.Error(), 400)
		return
	}

	name := sanitizeName(r.FormValue("name"))
	if name == "" {
		http.Error(w, "missing name", 400)
		return
	}

	// Read current wg conf
	b, err := os.ReadFile(a.Cfg.WGConfPath)
	if err != nil {
		http.Error(w, "cannot read wg conf: "+err.Error(), 500)
		return
	}
	confText := string(b)

	// Determine client's tunnel IP from generated client conf (best-effort)
	clientIP := ""
	confPath := filepath.Join(a.Cfg.OutputDir, name, fmt.Sprintf("%s.conf", name))
	if cb, err := os.ReadFile(confPath); err == nil {
		clientIP = parseClientAddress(cb)
	}

	newText, removed := removeClientFromWGConf(confText, name, clientIP)
	if !removed {
		http.Error(w, "client not found in wg config: "+name, 404)
		return
	}

	if err := os.WriteFile(a.Cfg.WGConfPath, []byte(newText), 0600); err != nil {
		http.Error(w, "cannot write wg conf: "+err.Error(), 500)
		return
	}
	if err := restartWG(a.Cfg.WGIf); err != nil {
		http.Error(w, "wg restart failed: "+err.Error(), 500)
		return
	}

	// Delete client folder
	_ = os.RemoveAll(filepath.Join(a.Cfg.OutputDir, name))

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handleBundleZip(w http.ResponseWriter, r *http.Request) {
	base := path.Base(r.URL.Path)
	if !strings.HasSuffix(base, ".zip") {
		http.Error(w, "bad zip name", 400)
		return
	}
	name := sanitizeName(strings.TrimSuffix(base, ".zip"))
	if name == "" {
		http.Error(w, "bad client name", 400)
		return
	}

	clientDir := filepath.Join(a.Cfg.OutputDir, name)
	if st, err := os.Stat(clientDir); err != nil || !st.IsDir() {
		http.Error(w, "client not found", 404)
		return
	}

	// NEW: include install_client.sh
	want := []string{
		fmt.Sprintf("%s.conf", name),
		fmt.Sprintf("%s_alt.conf", name),
		fmt.Sprintf("%s.png", name),
		"install_all.ps1",
		"install_client.sh",
		"README_WINDOWS.txt",
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, name))

	zw := zip.NewWriter(w)
	defer zw.Close()

	for _, fn := range want {
		p := filepath.Join(clientDir, fn)
		b, err := os.ReadFile(p)
		if err != nil {
			http.Error(w, "missing file in bundle: "+fn, 500)
			return
		}
		fh := &zip.FileHeader{Name: fn, Method: zip.Deflate}
		fh.SetModTime(time.Now())
		fw, err := zw.CreateHeader(fh)
		if err != nil {
			http.Error(w, "zip create failed: "+err.Error(), 500)
			return
		}
		if _, err := fw.Write(b); err != nil {
			http.Error(w, "zip write failed: "+err.Error(), 500)
			return
		}
	}
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = regexp.MustCompile(`[^a-z0-9_-]+`).ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return ""
	}
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

func hasClientMarker(confText, name string) bool {
	needle := "# " + name
	for _, line := range strings.Split(confText, "\n") {
		if strings.TrimSpace(line) == needle {
			return true
		}
	}
	return false
}

func parseClientAddress(conf []byte) string {
	re := regexp.MustCompile(`(?m)^\s*Address\s*=\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\/\d+\s*$`)
	m := re.FindSubmatch(conf)
	if len(m) == 2 {
		return string(m[1])
	}
	return ""
}

func removeClientFromWGConf(confText, name string, clientIP string) (string, bool) {
	lines := strings.Split(confText, "\n")
	trim := func(s string) string { return strings.TrimSpace(s) }

	// 1) Remove block starting at "# name" until next "# " marker or EOF
	start := -1
	for i := 0; i < len(lines); i++ {
		if trim(lines[i]) == "# "+name {
			start = i
			break
		}
	}
	if start != -1 {
		end := start + 1
		for end < len(lines) {
			if end != start && strings.HasPrefix(trim(lines[end]), "# ") {
				break
			}
			end++
		}
		return spliceDelete(lines, start, end), true
	}

	// 2) Fallback: remove [Peer] whose AllowedIPs contains clientIP/32
	if clientIP != "" {
		for i := 0; i < len(lines); i++ {
			if trim(lines[i]) == "[Peer]" {
				blockStart := i
				if i-1 >= 0 && strings.HasPrefix(trim(lines[i-1]), "# ") {
					blockStart = i - 1
				}
				end := i + 1
				found := false
				for end < len(lines) && trim(lines[end]) != "[Peer]" {
					if strings.HasPrefix(trim(lines[end]), "AllowedIPs") && strings.Contains(trim(lines[end]), clientIP+"/32") {
						found = true
					}
					if end != blockStart && strings.HasPrefix(trim(lines[end]), "# ") {
						break
					}
					end++
				}
				if found {
					return spliceDelete(lines, blockStart, end), true
				}
			}
		}
	}

	return confText, false
}

func spliceDelete(lines []string, start, end int) string {
	var out []string
	out = append(out, lines[:start]...)
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	rest := lines[end:]
	for len(rest) > 0 && strings.TrimSpace(rest[0]) == "" {
		rest = rest[1:]
	}
	if len(out) > 0 && len(rest) > 0 {
		out = append(out, "")
	}
	out = append(out, rest...)
	return strings.Join(out, "\n")
}

func getServerPublicKey(iface string) (string, error) {
	out, err := exec.Command("wg", "show", iface, "public-key").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

func genWGKeypair() (priv string, pub string, err error) {
	privOut, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", err
	}
	priv = strings.TrimSpace(string(privOut))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	pubOut, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	pub = strings.TrimSpace(string(pubOut))
	return priv, pub, nil
}

func restartWG(iface string) error {
	out, err := exec.Command("systemctl", "restart", "wg-quick@"+iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

func makeQRPNG(conf string, outPath string) error {
	cmd := exec.Command("qrencode", "-o", outPath, "-t", "png")
	cmd.Stdin = strings.NewReader(conf)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

func nextClientIP(wgNet string, wgConf string) (net.IPNet, error) {
	_, cidr, _ := net.ParseCIDR(wgNet)
	used := map[string]bool{}
	re := regexp.MustCompile(`(?m)^\s*AllowedIPs\s*=\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*/\s*32\s*$`)
	for _, m := range re.FindAllStringSubmatch(wgConf, -1) {
		used[m[1]] = true
	}
	network := cidr.IP.Mask(cidr.Mask).To4()
	start := ipToUint32(network) + 2
	end := ipToUint32(lastIP(*cidr)) - 1
	for u := start; u <= end; u++ {
		ip := uint32ToIP(u)
		if !used[ip.String()] {
			return net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
	}
	return net.IPNet{}, fmt.Errorf("no free IPs")
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
func uint32ToIP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte((u>>16)&0xff), byte((u>>8)&0xff), byte(u&0xff)).To4()
}
func lastIP(n net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := n.Mask
	out := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

func (a *App) renderClientConf(clientPriv, clientIP, serverPub, endpointHost string, endpointPort int) string {
	var b bytes.Buffer
	b.WriteString("[Interface]\n")
	b.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPriv))
	b.WriteString(fmt.Sprintf("Address = %s\n", clientIP))
	if a.Cfg.ClientDNS != "" {
		b.WriteString(fmt.Sprintf("DNS = %s\n", a.Cfg.ClientDNS))
	}
	b.WriteString("\n[Peer]\n")
	b.WriteString(fmt.Sprintf("PublicKey = %s\n", serverPub))
	b.WriteString(fmt.Sprintf("AllowedIPs = %s\n", a.Cfg.AllowedLanCIDR))
	b.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", endpointHost, endpointPort))
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

func (a *App) listClients(confText string) []ClientRow {
	names := map[string]bool{}
	lines := strings.Split(confText, "\n")
	for i := 0; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "# ") {
			n := strings.TrimSpace(strings.TrimPrefix(l, "# "))
			n = sanitizeName(n)
			if n != "" {
				names[n] = true
			}
		}
	}

	var out []ClientRow
	for n := range names {
		fp := filepath.Join(a.Cfg.OutputDir, n)
		_, err := os.Stat(fp)
		out = append(out, ClientRow{
			Name:       n,
			HasFolder:  err == nil,
			FolderPath: fp,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// NEW: install_client.sh included in the ZIP.
// This is useful if the user downloaded the bundle on Linux/macOS or via Git Bash/WSL on Windows.
// It extracts and runs the PowerShell installer via powershell.exe if available (Git Bash/WSL),
// otherwise it prints clear instructions.
func (a *App) renderInstallClientSH(clientName string) string {
	return fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail

CLIENT="%s"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "[+] DodgeVPN client bundle for: $CLIENT"
echo "[+] Files are in: $DIR"
echo

if command -v powershell.exe >/dev/null 2>&1; then
  echo "[+] Detected powershell.exe (Git Bash / WSL). Running Windows installer..."
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$DIR\\install_all.ps1"
  exit 0
fi

if command -v pwsh >/dev/null 2>&1; then
  echo "[+] Detected pwsh (PowerShell 7). Running installer..."
  pwsh -NoProfile -ExecutionPolicy Bypass -File "$DIR/install_all.ps1"
  exit 0
fi

echo "[!] No PowerShell detected in this environment."
echo
echo "On Windows, open an Administrator PowerShell in this folder and run:"
echo "  powershell -NoProfile -ExecutionPolicy Bypass -File .\\install_all.ps1"
echo
`, clientName)
}

func (a *App) renderWindowsInstallAllPS1(clientName string) string {
	wireguardMSI := "https://download.wireguard.com/windows-client/wireguard-amd64-0.5.3.msi"
	npcapEXE := "https://npcap.com/dist/npcap-1.87.exe"
	udp2rawTarGz := "https://github.com/wangyu-/udp2raw-multiplatform/releases/download/20210111.0/udp2raw_mp_binaries.tar.gz"
	nssmZip := "https://nssm.cc/release/nssm-2.24.zip"

	udp2rawSvc := "udp2raw-wg"
	tunnelName := clientName

	udp2rawArgs := fmt.Sprintf("-c -l127.0.0.1:%d -r%s:%d -k %s --raw-mode easyfaketcp",
		a.Cfg.Udp2RawLocalPort, a.Cfg.EndpointPublicIP, a.Cfg.Udp2RawTcpPort, a.Cfg.Udp2RawPassword)

	mtu := a.Cfg.ClientMTU // -1 means disabled

	var ps strings.Builder
	ps.WriteString("$ErrorActionPreference = 'Stop'\n")
	ps.WriteString("$ProgressPreference = 'SilentlyContinue'\n\n")

	ps.WriteString("function Ensure-Admin {\n")
	ps.WriteString("  $id = [Security.Principal.WindowsIdentity]::GetCurrent()\n")
	ps.WriteString("  $p  = New-Object Security.Principal.WindowsPrincipal($id)\n")
	ps.WriteString("  if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {\n")
	ps.WriteString("    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File', $PSCommandPath)\n")
	ps.WriteString("    exit 0\n")
	ps.WriteString("  }\n")
	ps.WriteString("}\n\n")

	ps.WriteString("function Download($url, $out) {\n")
	ps.WriteString("  Write-Host \"Downloading $url -> $out\"\n")
	ps.WriteString("  Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing\n")
	ps.WriteString("}\n\n")

	ps.WriteString("Ensure-Admin\n\n")
	ps.WriteString("$root = Split-Path -Parent $PSCommandPath\n")
	ps.WriteString("Set-Location $root\n\n")

	ps.WriteString("$log = Join-Path $root 'install.log'\n")
	ps.WriteString("try { Stop-Transcript | Out-Null } catch { }\n")
	ps.WriteString("Start-Transcript -Path $log -Append | Out-Null\n")
	ps.WriteString("Write-Host ('Logging to: ' + $log)\n\n")

	ps.WriteString("try {\n")
	ps.WriteString("  $tools = Join-Path $root 'tools'\n")
	ps.WriteString("  New-Item -ItemType Directory -Force -Path $tools | Out-Null\n\n")

	ps.WriteString("  $wgMsi = Join-Path $tools 'wireguard.msi'\n")
	ps.WriteString("  if (-not (Test-Path $wgMsi)) { Download '" + wireguardMSI + "' $wgMsi }\n")
	ps.WriteString("  Write-Host 'Installing WireGuard silently...'\n")
	ps.WriteString("  Start-Process -FilePath 'msiexec.exe' -ArgumentList @('/i', $wgMsi, '/qn', '/norestart') -Wait\n\n")

	ps.WriteString("  $wgExe = Join-Path $env:ProgramFiles 'WireGuard\\wireguard.exe'\n")
	ps.WriteString("  if (-not (Test-Path $wgExe)) { $wgExe = Join-Path ${env:ProgramFiles(x86)} 'WireGuard\\wireguard.exe' }\n")
	ps.WriteString("  if (-not (Test-Path $wgExe)) { throw 'wireguard.exe not found after install' }\n\n")

	ps.WriteString("  Write-Host 'Installing/Starting WireGuardManager...'\n")
	ps.WriteString("  try { & $wgExe /installmanagerservice | Out-Null } catch { }\n")
	ps.WriteString("  Start-Service -Name 'WireGuardManager' -ErrorAction SilentlyContinue\n")
	ps.WriteString("  Start-Sleep -Seconds 2\n")
	ps.WriteString("  $m = Get-Service -Name 'WireGuardManager' -ErrorAction SilentlyContinue\n")
	ps.WriteString("  if (-not $m) { throw 'WireGuardManager service not found' }\n")
	ps.WriteString("  if ($m.Status -ne 'Running') { Start-Service -Name 'WireGuardManager'; Start-Sleep 2 }\n\n")

	ps.WriteString("  $npcapOem = Join-Path $root 'npcap-oem.exe'\n")
	ps.WriteString("  if (Test-Path $npcapOem) {\n")
	ps.WriteString("    Write-Host 'Npcap OEM detected. Silent install (/S)...'\n")
	ps.WriteString("    Start-Process -FilePath $npcapOem -ArgumentList @('/S') -Wait\n")
	ps.WriteString("  } else {\n")
	ps.WriteString("    $npcap = Join-Path $tools 'npcap.exe'\n")
	ps.WriteString("    if (-not (Test-Path $npcap)) { Download '" + npcapEXE + "' $npcap }\n")
	ps.WriteString("    Write-Host 'Installing Npcap FREE edition (GUI may appear; silent is OEM-only).'\n")
	ps.WriteString("    Start-Process -FilePath $npcap -Wait\n")
	ps.WriteString("  }\n\n")

	ps.WriteString("  $udpTar = Join-Path $tools 'udp2raw_mp_binaries.tar.gz'\n")
	ps.WriteString("  if (-not (Test-Path $udpTar)) { Download '" + udp2rawTarGz + "' $udpTar }\n")
	ps.WriteString("  Write-Host 'Extracting udp2raw...'\n")
	ps.WriteString("  Push-Location $tools\n")
	ps.WriteString("  try { tar -xzf $udpTar } finally { Pop-Location }\n")
	ps.WriteString("  $exe = Get-ChildItem -Path $tools -Recurse -File -ErrorAction SilentlyContinue |\n")
	ps.WriteString("    Where-Object { $_.Name -match '^udp2raw_mp.*\\.exe$' } |\n")
	ps.WriteString("    Sort-Object FullName |\n")
	ps.WriteString("    Select-Object -First 1\n")
	ps.WriteString("  if (-not $exe) { throw 'Could not find udp2raw_mp*.exe after extracting.' }\n")
	ps.WriteString("  Copy-Item $exe.FullName -Destination (Join-Path $root 'udp2raw_mp.exe') -Force\n\n")

	ps.WriteString("  $nssmZip = Join-Path $tools 'nssm.zip'\n")
	ps.WriteString("  if (-not (Test-Path $nssmZip)) { Download '" + nssmZip + "' $nssmZip }\n")
	ps.WriteString("  Write-Host 'Extracting NSSM...'\n")
	ps.WriteString("  $nssmDir = Join-Path $tools 'nssm'\n")
	ps.WriteString("  New-Item -ItemType Directory -Force -Path $nssmDir | Out-Null\n")
	ps.WriteString("  Expand-Archive -Force -Path $nssmZip -DestinationPath $nssmDir\n")
	ps.WriteString("  $nssmFound = Get-ChildItem -Path $nssmDir -Recurse -File -ErrorAction SilentlyContinue |\n")
	ps.WriteString("    Where-Object { $_.Name -ieq 'nssm.exe' -and $_.FullName -match 'win64' } |\n")
	ps.WriteString("    Select-Object -First 1\n")
	ps.WriteString("  if (-not $nssmFound) { throw 'Could not find nssm.exe (win64) after extracting.' }\n")
	ps.WriteString("  Copy-Item $nssmFound.FullName -Destination (Join-Path $root 'nssm.exe') -Force\n")
	ps.WriteString("  $nssmExe = Join-Path $root 'nssm.exe'\n")
	ps.WriteString("  if (-not (Test-Path $nssmExe)) { throw 'nssm.exe copy failed' }\n\n")

	ps.WriteString("  Write-Host 'Adding Windows Firewall rules...'\n")
	ps.WriteString("  $udp2rawPath = Join-Path $root 'udp2raw_mp.exe'\n")
	ps.WriteString("  if (-not (Test-Path $udp2rawPath)) { throw 'udp2raw_mp.exe missing in bundle folder' }\n")
	ps.WriteString(fmt.Sprintf("  $tcpPort = %d\n", a.Cfg.Udp2RawTcpPort))
	ps.WriteString(fmt.Sprintf("  $udpPort = %d\n", a.Cfg.Udp2RawLocalPort))
	ps.WriteString("  $ruleBase = 'WG-UDP2RAW-" + escapeForSingleQuotedPS(clientName) + "'\n")
	ps.WriteString("  netsh advfirewall firewall delete rule name=\"$ruleBase WireGuard IN\"  | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall delete rule name=\"$ruleBase WireGuard OUT\" | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall delete rule name=\"$ruleBase udp2raw IN\"    | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall delete rule name=\"$ruleBase udp2raw OUT\"   | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall delete rule name=\"$ruleBase UDP localport\" | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall delete rule name=\"$ruleBase TCP remoteport\"| Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase WireGuard IN\"  dir=in  action=allow program=\"$wgExe\" enable=yes profile=any | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase WireGuard OUT\" dir=out action=allow program=\"$wgExe\" enable=yes profile=any | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase udp2raw IN\"    dir=in  action=allow program=\"$udp2rawPath\" enable=yes profile=any | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase udp2raw OUT\"   dir=out action=allow program=\"$udp2rawPath\" enable=yes profile=any | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase UDP localport\" dir=in  action=allow protocol=UDP localport=$udpPort profile=any | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase UDP localport\" dir=out action=allow protocol=UDP localport=$udpPort profile=any | Out-Null\n")
	ps.WriteString("  netsh advfirewall firewall add rule name=\"$ruleBase TCP remoteport\" dir=out action=allow protocol=TCP remoteport=$tcpPort profile=any | Out-Null\n\n")

	ps.WriteString("  Write-Host 'Creating udp2raw service...'\n")
	ps.WriteString("  $svcName = '" + udp2rawSvc + "'\n")
	ps.WriteString("  sc.exe query $svcName *> $null\n")
	ps.WriteString("  if ($LASTEXITCODE -eq 0) {\n")
	ps.WriteString("    Write-Host 'udp2raw service exists -> removing'\n")
	ps.WriteString("    sc.exe stop $svcName *> $null\n")
	ps.WriteString("    sc.exe delete $svcName *> $null\n")
	ps.WriteString("    Start-Sleep -Seconds 1\n")
	ps.WriteString("  }\n")
	ps.WriteString("  $udpArgs = '" + escapeForSingleQuotedPS(udp2rawArgs) + "'\n")
	ps.WriteString("  & $nssmExe install $svcName $udp2rawPath\n")
	ps.WriteString("  & $nssmExe set $svcName AppDirectory $root\n")
	ps.WriteString("  & $nssmExe set $svcName AppParameters $udpArgs\n")
	ps.WriteString("  & $nssmExe set $svcName Start SERVICE_AUTO_START\n")
	ps.WriteString("  & $nssmExe set $svcName AppStdout (Join-Path $root 'udp2raw.log')\n")
	ps.WriteString("  & $nssmExe set $svcName AppStderr (Join-Path $root 'udp2raw.err.log')\n")
	ps.WriteString("  & $nssmExe set $svcName AppRotateFiles 1\n")
	ps.WriteString("  & $nssmExe set $svcName AppRotateOnline 1\n")
	ps.WriteString("  & $nssmExe set $svcName AppRotateBytes 1048576\n")
	ps.WriteString("  & $nssmExe set $svcName AppRotateSeconds 86400\n")
	ps.WriteString("  sc.exe start $svcName\n")
	ps.WriteString("  Start-Sleep -Seconds 2\n")
	ps.WriteString("  $s = Get-Service -Name $svcName -ErrorAction SilentlyContinue\n")
	ps.WriteString("  if (-not $s) { throw 'udp2raw service was NOT created (Get-Service failed)' }\n")
	ps.WriteString("  if ($s.Status -ne 'Running') { throw ('udp2raw service not running; see udp2raw.err.log; status=' + $s.Status) }\n\n")

	// Manager import first -> dpapi
	ps.WriteString("  Write-Host 'Importing tunnel into WireGuard GUI store (Manager)...'\n")
	ps.WriteString("  $tunnelName = '" + escapeForSingleQuotedPS(tunnelName) + "'\n")
	ps.WriteString("  $confLocal = Join-Path $root ($tunnelName + '.conf')\n")
	ps.WriteString("  if (-not (Test-Path $confLocal)) { throw ('missing conf in bundle: ' + $confLocal) }\n")
	ps.WriteString("  $guiDir = Join-Path $env:ProgramFiles 'WireGuard\\Data\\Configurations'\n")
	ps.WriteString("  if (-not (Test-Path (Split-Path $guiDir -Parent))) { $guiDir = Join-Path ${env:ProgramFiles(x86)} 'WireGuard\\Data\\Configurations' }\n")
	ps.WriteString("  if (-not (Test-Path (Split-Path $guiDir -Parent))) { throw 'WireGuard GUI Data folder not found' }\n")
	ps.WriteString("  New-Item -ItemType Directory -Force -Path $guiDir | Out-Null\n")
	ps.WriteString("  $guiPlain = Join-Path $guiDir ($tunnelName + '.conf')\n")
	ps.WriteString("  $guiDpapi = Join-Path $guiDir ($tunnelName + '.conf.dpapi')\n")
	ps.WriteString("  if (Test-Path $guiPlain) { Remove-Item -Force $guiPlain -ErrorAction SilentlyContinue }\n")
	ps.WriteString("  Copy-Item -Force $confLocal $guiPlain\n")
	ps.WriteString("  Write-Host ('Dropped .conf into: ' + $guiPlain)\n")
	ps.WriteString("  $ok = $false\n")
	ps.WriteString("  for ($i=0; $i -lt 60; $i++) {\n")
	ps.WriteString("    if (Test-Path $guiDpapi) { $ok = $true; break }\n")
	ps.WriteString("    Start-Sleep -Milliseconds 500\n")
	ps.WriteString("  }\n")
	ps.WriteString("  if (-not $ok) { throw 'Manager did not create .conf.dpapi (import failed).' }\n")
	ps.WriteString("  Write-Host ('Manager created: ' + $guiDpapi)\n\n")

	// Install tunnel from dpapi
	ps.WriteString("  Write-Host 'Installing tunnel service from .conf.dpapi...'\n")
	ps.WriteString("  try { & $wgExe /uninstalltunnelservice $tunnelName | Out-Null } catch { }\n")
	ps.WriteString("  Start-Sleep -Seconds 1\n")
	ps.WriteString("  & $wgExe /installtunnelservice $guiDpapi\n")
	ps.WriteString("  if ($LASTEXITCODE -ne 0) { throw ('wireguard.exe installtunnelservice failed exit ' + $LASTEXITCODE) }\n")
	ps.WriteString("  Start-Sleep -Seconds 2\n")
	ps.WriteString("  $wgSvc = 'WireGuardTunnel$' + $tunnelName\n")
	ps.WriteString("  $ws = Get-Service -Name $wgSvc -ErrorAction SilentlyContinue\n")
	ps.WriteString("  if (-not $ws) { throw ('WireGuard tunnel service not created: ' + $wgSvc) }\n")
	ps.WriteString("  Start-Service -Name $wgSvc -ErrorAction SilentlyContinue\n")
	ps.WriteString("  Start-Sleep -Seconds 2\n")
	ps.WriteString("  $ws = Get-Service -Name $wgSvc -ErrorAction SilentlyContinue\n")
	ps.WriteString("  if ($ws.Status -ne 'Running') { throw 'WireGuard tunnel service not running' }\n\n")

	// Optional MTU via netsh (only if -MTU provided)
	ps.WriteString(fmt.Sprintf("  $desiredMtu = %d\n", mtu))
	ps.WriteString("  if ($desiredMtu -ge 0) {\n")
	ps.WriteString("    Write-Host 'Applying MTU via netsh (post-up)...'\n")
	ps.WriteString("    $ifName = $null\n")
	ps.WriteString("    try {\n")
	ps.WriteString("      $ifName = (Get-NetAdapter -IncludeHidden | Where-Object { $_.InterfaceDescription -like '*WireGuard Tunnel*' -and $_.Status -eq 'Up' } | Select-Object -First 1 -ExpandProperty Name)\n")
	ps.WriteString("    } catch { }\n")
	ps.WriteString("    if (-not $ifName) {\n")
	ps.WriteString("      try { $ifName = (Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -like ('*' + $tunnelName + '*') } | Select-Object -First 1 -ExpandProperty Name) } catch { }\n")
	ps.WriteString("    }\n")
	ps.WriteString("    if ($ifName) {\n")
	ps.WriteString("      Write-Host ('Setting MTU on interface: ' + $ifName)\n")
	ps.WriteString("      cmd /c \"netsh interface ipv4 set subinterface \\\"$ifName\\\" mtu=$desiredMtu store=persistent\" | Out-String | Write-Host\n")
	ps.WriteString("      cmd /c \"netsh interface ipv6 set subinterface \\\"$ifName\\\" mtu=$desiredMtu store=persistent\" | Out-String | Write-Host\n")
	ps.WriteString("    } else {\n")
	ps.WriteString("      Write-Host 'WARNING: Could not find WireGuard adapter name to set MTU.'\n")
	ps.WriteString("      Get-NetAdapter -IncludeHidden | Format-Table -AutoSize | Out-String | Write-Host\n")
	ps.WriteString("    }\n")
	ps.WriteString("  } else {\n")
	ps.WriteString("    Write-Host 'MTU not requested (no -MTU on server); skipping.'\n")
	ps.WriteString("  }\n\n")

	ps.WriteString("  try { Start-Process -FilePath $wgExe | Out-Null } catch { }\n")
	ps.WriteString("  Write-Host 'SUCCESS: udp2raw + WireGuard installed; tunnel imported to GUI store and running.'\n")
	ps.WriteString("}\n")
	ps.WriteString("catch {\n")
	ps.WriteString("  Write-Host 'FAILED:'\n")
	ps.WriteString("  Write-Host $_\n")
	ps.WriteString("  throw\n")
	ps.WriteString("}\n")
	ps.WriteString("finally {\n")
	ps.WriteString("  try { Stop-Transcript | Out-Null } catch { }\n")
	ps.WriteString("}\n")

	return ps.String()
}

func escapeForSingleQuotedPS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func (a *App) renderWindowsReadme(clientName string) string {
	mtuLine := "MTU: disabled (no -MTU used on server)"
	if a.Cfg.ClientMTU != -1 {
		mtuLine = fmt.Sprintf("MTU: enabled -> %d via netsh post-up", a.Cfg.ClientMTU)
	}
	return strings.Join([]string{
		"Windows FULL automation",
		"=======================",
		"",
		"Tunnel is imported into WireGuard GUI store first (.conf.dpapi),",
		"then tunnel service is installed from that dpapi so it appears in GUI.",
		"",
		mtuLine,
		"",
		"Run as Administrator:",
		"  powershell -NoProfile -ExecutionPolicy Bypass -File .\\install_all.ps1",
		"",
		"Alternative (Linux/macOS/Git Bash/WSL):",
		"  ./install_client.sh",
		"",
		"Logs:",
		"- install.log (full output transcript)",
		"- udp2raw.log / udp2raw.err.log",
	}, "\r\n")
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

var indexHTML = `
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>DodgeVPN (WireGuard + udp2raw)</title>
  <style>
    body { font-family: sans-serif; margin: 30px; max-width: 1080px; }
    .box { border: 1px solid #ccc; padding: 16px; border-radius: 12px; margin-bottom: 18px; }
    input { padding: 10px; width: 340px; font-size: 16px; }
    button { padding: 10px 16px; font-size: 16px; cursor: pointer; }
    code { background: #f4f4f4; padding: 2px 6px; }
    .ok { margin-top: 18px; padding: 16px; border-radius: 12px; border: 1px solid #9bd59b; background: #f5fff5; }
    .small { color: #666; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #eee; padding: 10px; text-align: left; }
    .danger { background: #fff3f3; border: 1px solid #f1bcbc; }
  </style>
</head>
<body>
  <h2>DodgeVPN WebUI</h2>

  <div class="box">
    <p><b>Interface:</b> <code>{{.WGIf}}</code></p>
    <p><b>Config:</b> <code>{{.WGConf}}</code></p>
    <p><b>WG net:</b> <code>{{.WGNet}}</code></p>
    <p><b>Allowed LAN:</b> <code>{{.AllowedLan}}</code> (NO 0.0.0.0/0)</p>
    <p><b>udp2raw endpoint:</b> <code>{{.Endpoint}}:{{.Udp2RawTcpPort}}</code></p>
    <p><b>udp2raw password:</b> <code>{{.Udp2RawPass}}</code></p>
    <p><b>Windows MTU:</b> <code>{{.ClientMTU}}</code> (disabled unless server started with <code>-MTU</code>)</p>

    <hr>
    <form method="POST" action="/add">
      <p>
        <label>Client name:</label><br>
        <input name="name" placeholder="e.g. franco_laptop" required>
      </p>
      <button type="submit">Add client</button>
    </form>
  </div>

  {{if .Last}}
    <div class="ok">
      <h3>Created: {{.Last.Name}}</h3>
      <p><b>Tunnel IP:</b> <code>{{.Last.ClientIP}}</code></p>
      <p class="small">Folder: <code>{{.Last.OutDir}}</code></p>
      <p><a href="{{.Last.ZipURL}}"><b>⬇ Download ZIP bundle</b></a></p>
      <p class="small">Created at: {{.Last.CreatedAt}}</p>
    </div>
  {{end}}

  <div class="box danger">
    <h3>Existing clients</h3>
    <p class="small">Parsed from <code># clientname</code> markers inside the WireGuard server config.</p>
    {{if .Clients}}
    <table>
      <thead>
        <tr><th>Name</th><th>Client folder</th><th>Actions</th></tr>
      </thead>
      <tbody>
        {{range .Clients}}
        <tr>
          <td><code>{{.Name}}</code></td>
          <td>
            {{if .HasFolder}}
              <span class="small">exists:</span> <code>{{.FolderPath}}</code>
            {{else}}
              <span class="small">missing</span>
            {{end}}
          </td>
          <td>
            <form method="POST" action="/delete" onsubmit="return confirm('Delete client {{.Name}} from server config and remove files?');" style="margin:0;">
              <input type="hidden" name="name" value="{{.Name}}">
              <button type="submit">Delete</button>
            </form>
          </td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
      <p class="small">No clients found yet.</p>
    {{end}}
  </div>

</body>
</html>
`

