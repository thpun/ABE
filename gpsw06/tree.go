package gpsw06

type operator uint

const (
	// Unexported constants
	or operator = iota
	and
)

type Tree struct {
}

func (t *Tree) satisfy([]attribute) bool {

}
