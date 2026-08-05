package frontend

// packageImportAliases maps a distribution name to the import root it is used
// under, for the cases where the two differ. A package absent here is imported
// under its own name.
//
// Without this, scoping a binding gated on `PyYAML` to calls on `PyYAML` would
// match nothing, because the code says `import yaml` -- the true positives
// would disappear silently.
var packageImportAliases = map[string][]string{
	"PyYAML":            {"yaml"},
	"beautifulsoup4":    {"bs4"},
	"python-dateutil":   {"dateutil"},
	"Pillow":            {"PIL"},
	"protobuf":          {"google"},
	"scikit-learn":      {"sklearn"},
	"opencv-python":     {"cv2"},
	"attrs":             {"attr"},
	"msgpack-python":    {"msgpack"},
	"PyJWT":             {"jwt"},
	"pycryptodome":      {"Crypto"},
	"pycryptodomex":     {"Cryptodome"},
	"python-magic":      {"magic"},
	"Django":            {"django"},
	"Flask":             {"flask"},
	"PySocks":           {"socks"},
	"python-jose":       {"jose"},
	"PyNaCl":            {"nacl"},
	"Twisted":           {"twisted"},
	"pyOpenSSL":         {"OpenSSL"},
	"ruamel.yaml":       {"ruamel"},
	"typing-extensions": {"typing_extensions"},
}

// importNamesForPackage returns every import root a distribution can appear
// under, starting with the distribution name itself.
func importNamesForPackage(pkg string) []string {
	out := []string{pkg}
	return append(out, packageImportAliases[pkg]...)
}
