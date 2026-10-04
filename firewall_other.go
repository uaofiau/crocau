//go:build !windows

package main

func fwEnsure() error    { return nil }
func fwPresent() bool    { return true }
func fwRemove() error    { return nil }
func fwInstallMain() int { return 0 }
func fwRemoveMain() int  { return 0 }
func fwSelfTest() int    { testLogf("FIREWALL: пропущено (не Windows)"); return 0 }
