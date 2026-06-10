package usg

import (
	"encoding/binary"
	"encoding/json"
	"sync/atomic"

	badger "github.com/dgraph-io/badger/v4"
)

// BadgerStore is the persistent fact store (docs/adr/0002). The graph is
// modeled as key-value with a 0x00 separator (never present in textual ids), so
// concept lookups and out/in-edge traversal are ordered prefix scans:
//
//	n\0<id>                      -> Node
//	eo\0<src>\0<seq>             -> Edge   (out-edges of src)
//	ei\0<dst>\0<seq>             -> Edge   (in-edges of dst)
//	lc\0<concept>\0<nodeID>      -> Label  (nodes carrying a concept)
//	ln\0<nodeID>\0<concept>      -> Label  (labels on a node)
type BadgerStore struct {
	db  *badger.DB
	seq atomic.Uint64
}

const sep = "\x00"

// OpenBadger opens (or creates) a BadgerDB-backed store at path. Use ":memory:"
// for an in-memory Badger (testing); otherwise a directory path.
func OpenBadger(path string) (*BadgerStore, error) {
	var opts badger.Options
	if path == ":memory:" {
		opts = badger.DefaultOptions("").WithInMemory(true)
	} else {
		opts = badger.DefaultOptions(path)
	}
	opts = opts.WithLogger(nil)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &BadgerStore{db: db}, nil
}

func (s *BadgerStore) set(key string, val any) error {
	b, err := json.Marshal(val)
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), b)
	})
}

func (s *BadgerStore) seqKey() string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], s.seq.Add(1))
	return string(b[:])
}

func (s *BadgerStore) AddNode(n Node) error {
	return s.set("n"+sep+n.ID, n)
}

func (s *BadgerStore) AddEdge(e Edge) error {
	k := s.seqKey()
	if err := s.set("eo"+sep+e.Src+sep+k, e); err != nil {
		return err
	}
	return s.set("ei"+sep+e.Dst+sep+k, e)
}

func (s *BadgerStore) AddLabel(nodeID string, l Label) error {
	if err := s.set("lc"+sep+l.Concept+sep+nodeID, l); err != nil {
		return err
	}
	return s.set("ln"+sep+nodeID+sep+l.Concept, l)
}

func (s *BadgerStore) GetNode(id string) (Node, bool, error) {
	var n Node
	found := false
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("n" + sep + id))
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return item.Value(func(v []byte) error { return json.Unmarshal(v, &n) })
	})
	return n, found, err
}

func (s *BadgerStore) edges(prefix, edgeType string) ([]Edge, error) {
	var out []Edge
	err := s.scan(prefix, func(_ string, v []byte) error {
		var e Edge
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		if edgeType == "" || e.Type == edgeType {
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

func (s *BadgerStore) OutEdges(src, edgeType string) ([]Edge, error) {
	return s.edges("eo"+sep+src+sep, edgeType)
}

func (s *BadgerStore) InEdges(dst, edgeType string) ([]Edge, error) {
	return s.edges("ei"+sep+dst+sep, edgeType)
}

func (s *BadgerStore) NodesWithConcept(concept string) ([]string, error) {
	prefix := "lc" + sep + concept + sep
	var out []string
	err := s.scan(prefix, func(key string, _ []byte) error {
		out = append(out, key[len(prefix):]) // suffix = nodeID
		return nil
	})
	return out, err
}

func (s *BadgerStore) NodesOfType(nodeType string) ([]string, error) {
	var out []string
	err := s.scan("n"+sep, func(_ string, v []byte) error {
		var n Node
		if err := json.Unmarshal(v, &n); err != nil {
			return err
		}
		if n.Type == nodeType {
			out = append(out, n.ID)
		}
		return nil
	})
	return out, err
}

func (s *BadgerStore) AllNodes() ([]Node, error) {
	var out []Node
	err := s.scan("n"+sep, func(_ string, v []byte) error {
		var n Node
		if err := json.Unmarshal(v, &n); err != nil {
			return err
		}
		out = append(out, n)
		return nil
	})
	return out, err
}

func (s *BadgerStore) Labels(nodeID string) ([]Label, error) {
	var out []Label
	err := s.scan("ln"+sep+nodeID+sep, func(_ string, v []byte) error {
		var l Label
		if err := json.Unmarshal(v, &l); err != nil {
			return err
		}
		out = append(out, l)
		return nil
	})
	return out, err
}

func (s *BadgerStore) scan(prefix string, fn func(key string, val []byte) error) error {
	pb := []byte(prefix)
	return s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = pb
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(pb); it.ValidForPrefix(pb); it.Next() {
			item := it.Item()
			key := string(item.KeyCopy(nil))
			if err := item.Value(func(v []byte) error { return fn(key, v) }); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *BadgerStore) Close() error { return s.db.Close() }
