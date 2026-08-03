package sca

import "github.com/vyprai/vyql/usg"

func rangeStoreNodes(g usg.Store, fn func(usg.Node) bool) error {
	if rg, ok := g.(interface{ RangeNodes(func(usg.Node) bool) }); ok {
		rg.RangeNodes(fn)
		return nil
	}
	nodes, err := g.AllNodes()
	if err != nil {
		return err
	}
	for _, n := range nodes {
		if !fn(n) {
			break
		}
	}
	return nil
}
