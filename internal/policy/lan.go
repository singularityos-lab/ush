package policy

const (
	CategoryLan Category = "lan"
	LanResource          = "local-network"
)

func LanShared(e *Engine) bool {
	d, ok := e.Check(CategoryLan, LanResource)
	return ok && d == DecisionAllow
}
