package treesitter

import (
	"sync"

	tree_sitter "github.com/tree-sitter/go-tree-sitter"
)

// grammarMetadata is immutable after construction and shared by every file parsed with
// the same tree-sitter grammar. The Go binding turns Kind into a fresh Go string and
// ChildByFieldName into a freshly allocated C string on every call; both operations sit
// in the innermost CST walk. Resolving their integer forms once avoids that churn.
type grammarMetadata struct {
	kindNames []string
	fieldIDs  map[string]uint16
}

type grammarMetadataEntry struct {
	once sync.Once
	meta *grammarMetadata
}

var grammarMetadataEntries sync.Map // tree-sitter language pointer -> *grammarMetadataEntry

// treeFieldNames is the finite vocabulary used by the frontends. A frontend that adds a
// dynamic or new field name remains correct through nodeCache.field's fallback; adding a
// frequent literal here only moves that name onto the allocation-free path.
var treeFieldNames = [...]string{
	"alias", "alternative", "argument", "arguments", "array", "attribute", "attributes",
	"base", "block", "body", "bounds", "command_elements", "command_name", "condition",
	"consequence", "consequent", "constructor", "declarator", "definition", "else",
	"else_body", "expression", "field", "function", "hash", "import_clause", "index",
	"interfaces", "invocant", "key", "label", "left", "lhs", "macro", "member", "method",
	"module_name", "name", "object", "operand", "operator", "operators", "parameter",
	"parameters", "path", "pattern", "property", "receiver", "result", "rhs", "right",
	"scope", "size", "source", "subject", "subscript", "suffix", "superclass",
	"superclasses", "table", "target", "then", "type", "type_parameters", "value", "variable",
}

func metadataFor(n *tree_sitter.Node) *grammarMetadata {
	lang := n.Language()
	entryValue, _ := grammarMetadataEntries.LoadOrStore(lang.Inner, &grammarMetadataEntry{})
	entry := entryValue.(*grammarMetadataEntry)
	entry.once.Do(func() {
		kinds := make([]string, lang.NodeKindCount())
		for id := range kinds {
			kinds[id] = lang.NodeKindForId(uint16(id))
		}
		fields := make(map[string]uint16, len(treeFieldNames))
		for _, name := range treeFieldNames {
			fields[name] = lang.FieldIdForName(name)
		}
		entry.meta = &grammarMetadata{kindNames: kinds, fieldIDs: fields}
	})
	return entry.meta
}

// nodeCache is embedded in each language converter. Grammar metadata is shared across
// files; child slices are not, because their nodes belong to one parse tree.
type nodeCache struct {
	grammar *grammarMetadata
	named   map[uintptr][]*tree_sitter.Node
	all     map[uintptr][]*tree_sitter.Node
}

func (c *nodeCache) ensure(n *tree_sitter.Node) *grammarMetadata {
	if c.grammar == nil {
		c.grammar = metadataFor(n)
	}
	return c.grammar
}

func (c *nodeCache) kind(n *tree_sitter.Node) string {
	if n == nil {
		return ""
	}
	meta := c.ensure(n)
	id := n.KindId()
	if int(id) < len(meta.kindNames) {
		return meta.kindNames[id]
	}
	return n.Kind()
}

func (c *nodeCache) field(n *tree_sitter.Node, name string) *tree_sitter.Node {
	if n == nil {
		return nil
	}
	if id, ok := c.ensure(n).fieldIDs[name]; ok {
		if id == 0 {
			return nil
		}
		return n.ChildByFieldId(id)
	}
	return n.ChildByFieldName(name)
}

func (c *nodeCache) namedChildren(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	c.ensure(n)
	if c.named == nil {
		c.named = make(map[uintptr][]*tree_sitter.Node)
	}
	id := n.Id()
	if kids, ok := c.named[id]; ok {
		return kids
	}
	kids := namedChildren(n)
	c.named[id] = kids
	return kids
}

func (c *nodeCache) children(n *tree_sitter.Node) []*tree_sitter.Node {
	if n == nil {
		return nil
	}
	c.ensure(n)
	if c.all == nil {
		c.all = make(map[uintptr][]*tree_sitter.Node)
	}
	id := n.Id()
	if kids, ok := c.all[id]; ok {
		return kids
	}
	kids := children(n)
	c.all[id] = kids
	return kids
}
