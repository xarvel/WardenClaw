// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// dropPrivileges: drops the child's uid/gid (hardened install). Supports a user "name", "uid",
// "uid:gid". uid goes last, otherwise after the uid change there is no right to change gid/groups.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

func resolveChildUser(spec string) (uid, gid int, groups []int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil, errors.New("empty user")
	}
	// uid[:gid] as numbers
	if u, err := parseUIDGID(spec); err == nil {
		return u.uid, u.gid, []int{u.gid}, nil
	}
	usr, err := user.Lookup(spec)
	if err != nil {
		return 0, 0, nil, err
	}
	uid, _ = strconv.Atoi(usr.Uid)
	gid, _ = strconv.Atoi(usr.Gid)
	gs, _ := usr.GroupIds()
	groups = append(groups, gid)
	for _, g := range gs {
		if n, e := strconv.Atoi(g); e == nil && n != gid {
			groups = append(groups, n)
		}
	}
	return uid, gid, groups, nil
}

type uidgid struct{ uid, gid int }

func parseUIDGID(spec string) (uidgid, error) {
	us, gs, hasGid := strings.Cut(spec, ":")
	uid, err := strconv.Atoi(us)
	if err != nil {
		return uidgid{}, err
	}
	gid := uid
	if hasGid {
		if gid, err = strconv.Atoi(gs); err != nil {
			return uidgid{}, err
		}
	} else {
		// no ':' and a numeric uid, but the primary group must be found; gid=uid is the default
		if u, e := user.LookupId(us); e == nil {
			if g, e2 := strconv.Atoi(u.Gid); e2 == nil {
				gid = g
			}
		}
	}
	return uidgid{uid, gid}, nil
}

func dropPrivileges(spec string) error {
	uid, gid, groups, err := resolveChildUser(spec)
	if err != nil {
		return err
	}
	if uid == 0 {
		return errors.New("refused: target uid=0 (the child must not be root)")
	}
	if err := syscall.Setgroups(groups); err != nil {
		return fmt.Errorf("setgroups %v: %w", groups, err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid %d: %w", gid, err)
	}
	if err := syscall.Setuid(uid); err != nil { // uid last
		if err == syscall.EPERM && syscall.Getuid() == 0 {
			return fmt.Errorf("setuid %d: %w (the process has no CAP_SETUID; in the system unit do not set User=root together with NoNewPrivileges=true, see deploy/wardend.system.service)", uid, err)
		}
		return fmt.Errorf("setuid %d: %w", uid, err)
	}
	// extra safety: make sure it is impossible to go back up
	if syscall.Getuid() != uid || syscall.Geteuid() != uid {
		return fmt.Errorf("uid not dropped: real=%d eff=%d", syscall.Getuid(), syscall.Geteuid())
	}
	return nil
}

// resetOOMScoreAdj: oom_score_adj is inherited on fork and survives exec. In the system unit
// wardend has OOMScoreAdjust=-500 (under memory pressure the kernel must kill the harness, not the
// supervisor); without a reset the harness would get the same -500 and the protection would lose
// its point. For the child a negative value is reset to 0; a non-negative one is left as is.
func resetOOMScoreAdj() error {
	const p = "/proc/self/oom_score_adj"
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	if v >= 0 {
		return nil
	}
	return os.WriteFile(p, []byte("0\n"), 0)
}
