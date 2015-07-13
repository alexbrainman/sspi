// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build windows

package sspi

import (
	"syscall"
	"time"
	"unsafe"
)

// TODO: add documentation

type PackageInfo struct {
	Capabilities uint32
	Version      uint16
	RPCID        uint16
	MaxToken     uint32
	Name         string
	Comment      string
}

func QueryPackageInfo(pkgname string) (*PackageInfo, error) {
	name, err := syscall.UTF16PtrFromString(pkgname)
	if err != nil {
		return nil, err
	}
	var pi *SecPkgInfo
	ret := QuerySecurityPackageInfo(name, &pi)
	if ret != SEC_E_OK {
		return nil, ret
	}
	defer FreeContextBuffer((*byte)(unsafe.Pointer(pi)))

	return &PackageInfo{
		Capabilities: pi.Capabilities,
		Version:      pi.Version,
		RPCID:        pi.RPCID,
		MaxToken:     pi.MaxToken,
		Name:         syscall.UTF16ToString((*[2 << 12]uint16)(unsafe.Pointer(pi.Name))[:]),
		Comment:      syscall.UTF16ToString((*[2 << 12]uint16)(unsafe.Pointer(pi.Comment))[:]),
	}, nil
}

type Credentials struct {
	Handle CredHandle
	expiry syscall.Filetime
}

func AcquireCredentials(pkgname string, creduse uint32, authdata *byte) (*Credentials, error) {
	name, err := syscall.UTF16PtrFromString(pkgname)
	if err != nil {
		return nil, err
	}
	var c Credentials
	ret := AcquireCredentialsHandle(nil, name, creduse, nil, authdata, 0, 0, &c.Handle, &c.expiry)
	if ret != SEC_E_OK {
		return nil, ret
	}
	return &c, nil
}

func (c *Credentials) Release() error {
	ret := FreeCredentialsHandle(&c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

func (c *Credentials) Expiry() time.Time {
	return time.Unix(0, c.expiry.Nanoseconds())
}

// TODO: add functions to display and manage RequestedFlags and EstablishedFlags fields.
// TODO: maybe get rid of RequestedFlags and EstablishedFlags fields, and replace them with input parameter for New...Context and return value of Update (instead of current bool parameter).

type updateFunc func(c *Context, h, newh *CtxtHandle, out, in *SecBufferDesc) syscall.Errno

type Context struct {
	Cred             *Credentials
	Handle           *CtxtHandle
	handle           CtxtHandle
	updFn            updateFunc
	expiry           syscall.Filetime
	RequestedFlags   uint32
	EstablishedFlags uint32
}

func newContext(cred *Credentials, flags uint32, updFn updateFunc, dst, src []byte) (nc *Context, authCompleted bool, n int, err error) {
	c := &Context{
		Cred:           cred,
		updFn:          updFn,
		RequestedFlags: flags,
	}
	authCompleted, n, err = c.Update(dst, src)
	if err != nil {
		return nil, authCompleted, 0, err
	}
	return c, authCompleted, n, nil
}

func NewClientContext(cred *Credentials, flags uint32, dst []byte) (c *Context, authCompleted bool, n int, err error) {
	return newContext(cred, flags, initialize, dst, nil)
}

func NewServerContext(cred *Credentials, flags uint32, dst, src []byte) (c *Context, authCompleted bool, n int, err error) {
	return newContext(cred, flags, accept, dst, src)
}

func initialize(c *Context, h, newh *CtxtHandle, out, in *SecBufferDesc) syscall.Errno {
	return InitializeSecurityContext(&c.Cred.Handle, h, nil, c.RequestedFlags,
		0, SECURITY_NATIVE_DREP, in, 0, newh, out, &c.EstablishedFlags, &c.expiry)
}

func accept(c *Context, h, newh *CtxtHandle, out, in *SecBufferDesc) syscall.Errno {
	return AcceptSecurityContext(&c.Cred.Handle, h, in, c.RequestedFlags,
		SECURITY_NATIVE_DREP, newh, out, &c.EstablishedFlags, &c.expiry)
}

func (c *Context) Update(dst, src []byte) (authCompleted bool, n int, err error) {
	// TODO: some of this buffer setup could be done once (when creating Context) and then reused here.
	inBuf := &SecBuffer{
		BufferType: SECBUFFER_TOKEN,
	}
	if len(src) > 0 {
		inBuf.BufferSize = uint32(len(src))
		inBuf.Buffer = &src[0]
	}
	inBufs := &SecBufferDesc{
		Version:      SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      inBuf,
	}

	outBuf := &SecBuffer{
		BufferType: SECBUFFER_TOKEN,
	}
	if len(dst) > 0 {
		outBuf.BufferSize = uint32(len(dst))
		outBuf.Buffer = &dst[0]
	}
	outBufs := &SecBufferDesc{
		Version:      SECBUFFER_VERSION,
		BuffersCount: 1,
		Buffers:      outBuf,
	}

	h := c.Handle
	if c.Handle == nil {
		c.Handle = &c.handle
	}

	ret := c.updFn(c, h, c.Handle, outBufs, inBufs)
	switch ret {
	case SEC_E_OK:
		// session established -> return success
		return true, int(outBuf.BufferSize), nil
	case SEC_I_COMPLETE_NEEDED, SEC_I_COMPLETE_AND_CONTINUE:
		ret = CompleteAuthToken(c.Handle, outBufs)
		if ret != SEC_E_OK {
			return false, 0, ret
		}
	case SEC_I_CONTINUE_NEEDED:
	default:
		return false, 0, ret
	}
	return false, int(outBuf.BufferSize), nil
}

func (c *Context) Release() error {
	ret := DeleteSecurityContext(c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

func (c *Context) Expiry() time.Time {
	return time.Unix(0, c.expiry.Nanoseconds())
}

// TODO: add comment to function doco that this "impersonation" is applied to current OS thread.
func (c *Context) ImpersonateUser() error {
	ret := ImpersonateSecurityContext(c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}

func (c *Context) RevertToSelf() error {
	ret := RevertSecurityContext(c.Handle)
	if ret != SEC_E_OK {
		return ret
	}
	return nil
}
