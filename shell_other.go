//go:build !windows

package main

func shellInstalled() bool          { return false }
func shellRegister() error          { return nil }
func shellUnregister() error        { return nil }
func shellCleanupLegacy()           {}
func shellSelfTest() (bool, string) { return true, "" }
