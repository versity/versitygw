// Copyright 2020 the authors.
//
// Licensed under the Apache License, Version 2.0 (the LICENSE-APACHE file) or
// the MIT license (the LICENSE-MIT file) at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// code modified from https://github.com/joshlf/go-acl

package acl

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strings"
	"syscall"
)

// ACL represents an access control list as defined
// in the POSIX.1e draft standard. If an ACL is not
// valid (see the IsValid method), the behavior of
// the functions and methods of this package is
// undefined.
type ACL []Entry

// ToUnix returns the unix permissions bitmask
// encoded by a. If a is not valid as defined
// by a.IsValid, the behavior of ToUnix is
// undefined.
func ToUnix(a ACL) os.FileMode {
	var perms os.FileMode
	for _, e := range a {
		switch e.Tag {
		case TagUserObj:
			perms |= (e.perms() << 6)
		case TagGroupObj:
			perms |= (e.perms() << 3)
		case TagOther:
			perms |= e.perms()
		}
	}
	return perms
}

// String implements the POSIX.1e short text form.
// For example:
//
//	u::rwx,g::r-x,o::---,u:dvader:r--,m::r--
//
// This output is produced by an ACL in which the file owner
// has read, write, and execute; the file group has read and
// execute; other has no permissions; the user dvader has
// read; and the mask is read.
func (a ACL) String() string {
	strs := make([]string, len(a))
	for i, e := range a {
		strs[i] = e.String()
	}
	return strings.Join(strs, ",")
}

// StringLong implements the POSIX.1e long text form.
// The long text form of the example given above is:
//
//	user::rwx
//	group::r-x
//	other::---
//	user:dvader:r--
//	mask::r--
func (a ACL) StringLong() string {
	lines := make([]string, len(a))
	mask := os.FileMode(7)
	for _, e := range a {
		if e.Tag == TagMask {
			mask = e.perms()
			break
		}
	}
	for i, e := range a {
		if (e.Tag == TagUser || e.Tag == TagGroupObj || e.Tag == TagGroup) &&
			mask|e.perms() != mask {
			effective := mask & e.perms()
			lines[i] = fmt.Sprintf("%-20s#effective:%s", e.StringLong(), permString(effective))
		} else {
			lines[i] = e.StringLong()
		}
	}
	return strings.Join(lines, "\n")
}

// Tag is the type of an ACL entry tag.
type Tag tag

const (
	TagUserObj  Tag = tagUserObj  // Permissions of the file owner
	TagUser         = tagUser     // Permissions of a specified user
	TagGroupObj     = tagGroupObj // Permissions of the file group
	TagGroup        = tagGroup    // Permissions of a specified group

	// Maximum allowed access rights of any entry
	// with the tag TagUser, TagGroupObj, or TagGroup
	TagMask  = tagMask
	TagOther = tagOther // Permissions of a process not matching any other entry
)

// String implements the POSIX.1e short text form.
func (t Tag) String() string {
	switch t {
	case TagUser, TagUserObj:
		return "u"
	case TagGroup, TagGroupObj:
		return "g"
	case TagOther:
		return "o"
	case TagMask:
		return "m"
	default:
		// TODO(joshlf): what to do in this case?
		return "?" // non-standard, but not specified in POSIX.1e
	}
}

// StringLong implements the POSIX.1e long text form.
func (t Tag) StringLong() string {
	switch t {
	case TagUser, TagUserObj:
		return "user"
	case TagGroup, TagGroupObj:
		return "group"
	case TagOther:
		return "other"
	case TagMask:
		return "mask"
	default:
		// TODO(joshlf): what to do in this case?
		return "????" // non-standard, but not specified in POSIX.1e
	}
}

// Entry represents an entry in an ACL.
type Entry struct {
	Tag Tag

	// TODO(joshlf): it would be nice if we could handle
	// the UID/user name or GID/group name transition
	// transparently under the hood rather than pushing
	// the responsibility to the user. However, there are
	// some subtle considerations:
	//   - It must be valid to provide a UID/GID for a
	//     user or group that does not exist (setfactl
	//     supports this)
	//   - If the qualifier can be either a UID/GID or
	//     a user name/group name, there should probably
	//     be a better way of encoding it (that is,
	//     better than just setting it to one or the
	//     other and letting the user implement custom
	//     logic to tell the difference)

	// The Qualifier specifies what entity (user or group)
	// this entry applies to. If the Tag is TagUser, it is
	// a UID; if the Tag is TagGroup, it is a GID; otherwise
	// the field is ignored. Note that the qualifier must
	// be a UID or GID - it cannot be, for example, a user name.
	Qualifier string

	// ACL permissions are taken from a traditional rwx
	// (read/write/execute) permissions vector. The Perms
	// field stores these as the lowest three bits -
	// the bits in any higher positions are ignored.
	Perms os.FileMode
}

// Use e.perms() to make sure that only
// the lowest three bits are set - some
// algorithms may inadvertently break
// otherwise (including libacl itself).
func (e Entry) perms() os.FileMode { return 7 & e.Perms }

var permStrings = []string{
	0: "---",
	1: "--x",
	2: "-w-",
	3: "-wx",
	4: "r--",
	5: "r-x",
	6: "rw-",
	7: "rwx",
}

// assumes perm has only lowest three bits set
func permString(perm os.FileMode) string {
	return permStrings[int(perm)]
}

// String implements the POSIX.1e short text form.
func (e Entry) String() string {
	middle := "::"
	if e.Tag == TagUser || e.Tag == TagGroup {
		middle = ":" + formatQualifier(e.Qualifier, e.Tag) + ":"
	}
	return fmt.Sprintf("%s%s%s", e.Tag, middle, permString(e.perms()))
}

// StringLong implements the POSIX.1e long text form.
func (e Entry) StringLong() string {
	middle := "::"
	if e.Tag == TagUser || e.Tag == TagGroup {
		middle = ":" + formatQualifier(e.Qualifier, e.Tag) + ":"
	}
	return fmt.Sprintf("%s%s%s", e.Tag.StringLong(), middle, permString(e.perms()))
}

// overwrite in other files to implement platform-specific behavior
var formatQualifier = func(q string, _ Tag) string { return q }

/*
	NOTE: This implementation is largely based on Linux's libacl.
*/

type tag int

const (
	// defined in sys/acl.h
	tagUndefined Tag = 0x00
	tagUserObj   Tag = 0x01
	tagUser      Tag = 0x02
	tagGroupObj  Tag = 0x04
	tagGroup     Tag = 0x08
	tagMask      Tag = 0x10
	tagOther     Tag = 0x20

	// defined in include/acl_ea.h (see libacl source)
	aclEAAccess    = "system.posix_acl_access"
	aclEADefault   = "system.posix_acl_default"
	aclEAVersion   = 2
	aclEAEntrySize = 8
	aclUndefinedID = math.MaxUint32 // defined in sys/acl.h
)

func AclFromXattr(xattr []byte) (acl ACL, err error) {
	if len(xattr) < 4 {
		return nil, syscall.EINVAL
	}
	version := binary.LittleEndian.Uint32(xattr)
	xattr = xattr[4:]
	if version != aclEAVersion {
		return nil, syscall.EINVAL
	}
	if len(xattr)%aclEAEntrySize != 0 {
		return nil, syscall.EINVAL
	}

	for len(xattr) > 0 {
		etag := binary.LittleEndian.Uint16(xattr)
		sperm := binary.LittleEndian.Uint16(xattr[2:])
		qid := binary.LittleEndian.Uint32(xattr[4:])

		ent := Entry{
			Tag:   Tag(etag),
			Perms: os.FileMode(sperm),
		}
		if ent.Tag == TagUser || ent.Tag == TagGroup {
			ent.Qualifier = fmt.Sprint(qid)
		}

		acl = append(acl, ent)
		xattr = xattr[8:]
	}

	return acl, nil
}
