//go:build !no_fakeshell && !plan9 && unix

package fakeshell

import "syscall"

const rootFSNonblock = syscall.O_NONBLOCK
