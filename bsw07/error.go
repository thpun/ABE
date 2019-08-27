package bsw07

import "errors"

var (
	ErrBadNodeJSON        = errors.New("bad structured json for node")
	ErrEncAttrNotExist    = errors.New("encrypted key not exist for such attribute")
	ErrInvalidG           = errors.New("could not find well-formed string describing g")
	ErrUnknownNodeType    = errors.New("unknown node type")
	ErrTreeNotSatisfied   = errors.New("ciphertext does not Satisfy decryption key policy")
	ErrSubsetAttrNotExist = errors.New("specified attribute does not exist in superset")
)
