package acl

import (
	"fmt"
	"os"
	"syscall"
)

const (
	Read os.FileMode = 1 << iota
)

func (a ACL) IsReadAllowed(uid, gid uint32) bool {
	return a.isAllowed(uid, gid, Read)
}

func (a ACL) isAllowed(uid, gid uint32, perm os.FileMode) bool {
	for _, e := range a {
		if e.matches(uid, gid) {
			return e.isAllowed(perm)
		}
	}
	return false
}

func (e Entry) matches(uid, gid uint32) bool {
	switch e.Tag {
	case TagUserObj:
		return e.Qualifier == fmt.Sprintf("%v", uid)
	case TagGroupObj:
		return e.Qualifier == fmt.Sprintf("%v", gid)
	case TagMask:
		return true
	case TagOther:
		return true
	}
	return false
}

func (e Entry) isAllowed(perm os.FileMode) bool {
	return e.Perms&perm != 0
}

func IsReadAllowed(fi os.FileInfo, uid, gid uint32) bool {
	fiuser := fi.Sys().(*syscall.Stat_t).Uid
	figroup := fi.Sys().(*syscall.Stat_t).Gid

	switch {
	case fiuser == uid:
		if fi.Mode()&0400 != 0 {
			return true
		}
	case figroup == gid:
		if fi.Mode()&0040 != 0 {
			return true
		}
	default:
		if fi.Mode()&0004 != 0 {
			return true
		}
	}
	return false
}
