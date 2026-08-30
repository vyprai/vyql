package treesitter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/internal/extract/nir"
)

// ccFormatTruncationObs runs the format-truncation observation over one C
// source and returns the emitted facts as "var=..;dest=..;reuse=..;guard=.."
// text.
func ccFormatTruncationObs(t *testing.T, src string) []string {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "send.c")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	prog, err := ExtractC([]string{file}, dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range prog.Modules[0].Body {
		fn, ok := st.(nir.FuncDef)
		if !ok {
			continue
		}
		for _, s := range fn.Body {
			es, ok := s.(nir.ExprStmt)
			if !ok {
				continue
			}
			call, ok := es.Value.(nir.Call)
			if !ok || call.Path != "analysis.format_length.truncation_unchecked" {
				continue
			}
			var parts []string
			for _, a := range call.Args {
				if konst, ok := a.(nir.Const); ok {
					parts = append(parts, konst.Value)
				}
			}
			out = append(out, strings.Join(parts, ";"))
		}
	}
	return out
}

func TestCFormatTruncationUncheckedReuseObservations(t *testing.T) {
	// The request idiom: the formatted length is sent from the fixed buffer
	// as an arithmetic count, with only the loop's progress condition naming
	// it in between. The progress comparison names another running count,
	// not a bound, so it is not a truncation check.
	got := ccFormatTruncationObs(t, `
#include <stdio.h>
void * miniwget3(const char * host, int s, const char * path) {
	char buf[2048];
	int n, len, sent;
	len = snprintf(buf, sizeof(buf), "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host);
	sent = 0;
	while (sent < len) {
		n = send(s, buf + sent, len - sent, 0);
		if (n < 0)
			return 0;
		sent += n;
	}
	return buf;
}
`)
	want := []string{"format=snprintf;var=len;dest=buf;reuse=call_argument;guard=missing_truncation_check"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("request idiom: got %q want %q", got, want)
	}

	// The datagram idiom: the same variable carries its own length argument.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
char * ssdpDiscover(int sudp) {
	char bufr[512];
	int n;
	n = snprintf(bufr, sizeof(bufr), "M-SEARCH\r\nST: %s\r\n", "ssdp:all");
	n = sendto(sudp, bufr, n, 0, 0, 0);
	return bufr;
}
`)
	want = []string{"format=snprintf;var=n;dest=bufr;reuse=call_argument;guard=missing_truncation_check"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("datagram idiom: got %q want %q", got, want)
	}

	// The body-building idiom: the formatted length moves the destination
	// pointer itself, so the writes that follow start past the buffer.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
char * simpleUPnPcommand2(const char * service, const char * action, struct UPNParg * args) {
	char soapbody[2048];
	char * p;
	int soapbodylen;
	soapbodylen = snprintf(soapbody, sizeof(soapbody), "<u:%s xmlns:u=\"%s\">", action, service);
	p = soapbody + soapbodylen;
	while (args->elt) {
		*(p++) = '<';
		args++;
	}
	return soapbody;
}
`)
	want = []string{"format=snprintf;var=soapbodylen;dest=soapbody;reuse=destination_pointer_offset;guard=missing_truncation_check"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("body-building idiom: got %q want %q", got, want)
	}

	// A captured length that no call receives and no pointer follows is
	// unused information, not a reuse.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
int log_line(const char * path) {
	char buf[2048];
	int len;
	len = snprintf(buf, sizeof(buf), "GET %s\r\n", path);
	return len < 0 ? -1 : 0;
}
`)
	if len(got) != 0 {
		t.Fatalf("unused length: got %q want none", got)
	}

	// The guard spellings that must clear, none of which is the literal
	// form the fix happened to use.
	for name, guard := range map[string]string{
		"cast":      "if ((unsigned int)len >= sizeof(buf)) return -1;",
		"named":     "if (len >= BUFSZ) return -1;",
		"mirrored":  "if (sizeof(buf) <= (unsigned int)len) return -1;",
		"disjunct":  "if (len < 0 || len >= sizeof(buf)) return -1;",
		"parameter": "if (len >= buflen) return -1;",
		"minus_one": "if (len > sizeof(buf) - 1) return -1;",
	} {
		got = ccFormatTruncationObs(t, `
#include <stdio.h>
int send_request(char *buf, int buflen, int s) {
	int len, sent, n;
	len = snprintf(buf, buflen, "GET\r\n");
	`+guard+`
	sent = 0;
	while (sent < len) {
		n = send(s, buf + sent, len - sent, 0);
		sent += n;
	}
	return 0;
}
`)
		if len(got) != 0 {
			t.Fatalf("%s guard: got %q want none", name, got)
		}
	}

	// The size argument consulted through a cast on the bound side.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
int send_request(char *buf, int buflen, int s) {
	int len, sent, n;
	len = snprintf(buf, buflen, "GET\r\n");
	if (buflen <= (int)len) return -1;
	sent = 0;
	while (sent < len) {
		n = send(s, buf + sent, len - sent, 0);
		sent += n;
	}
	return 0;
}
`)
	if len(got) != 0 {
		t.Fatalf("cast bound: got %q want none", got)
	}

	// The unbounded spellings have no bound to consult and stay out of this
	// fact entirely.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
int send_request(char *buf, int s) {
	int len, sent, n;
	len = sprintf(buf, "GET\r\n");
	sent = 0;
	while (sent < len) {
		n = send(s, buf + sent, len - sent, 0);
		sent += n;
	}
	return 0;
}
`)
	if len(got) != 0 {
		t.Fatalf("unbounded spelling: got %q want none", got)
	}

	// An inline declaration fuses with its type once whitespace is
	// stripped, so the assignment form is the only one recognised; the
	// fused spelling must not half-match onto the bare name either.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
int send_request(char *buf, int s) {
	int n, sent;
	int len = snprintf(buf, sizeof(buf), "GET\r\n");
	sent = 0;
	while (sent < len) {
		n = send(s, buf + sent, len - sent, 0);
		sent += n;
	}
	return 0;
}
`)
	if len(got) != 0 {
		t.Fatalf("inline declaration: got %q want none", got)
	}

	// A longer identifier ending in the captured name, compared against an
	// all-caps constant, is not the captured variable consulting a bound.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
int build(char *usn, int s) {
	char bufr[512];
	int n;
	n = snprintf(bufr, sizeof(bufr), "ST: %s\r\n", usn);
	if (usn != NULL)
		n = sendto(s, bufr, n, 0, 0, 0);
	return n;
}
`)
	want2 := []string{"format=snprintf;var=n;dest=bufr;reuse=call_argument;guard=missing_truncation_check"}
	if strings.Join(got, "|") != strings.Join(want2, "|") {
		t.Fatalf("suffixed identifier comparison: got %q want %q", got, want2)
	}

	// The captured length handed only to a printing call's format string is
	// a value being logged, not a byte count.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
void build_content(char *p, int n) {
	char line_buffer[80];
	int k;
	k = snprintf(line_buffer, sizeof(line_buffer), "%04d_%04d\r\n", n, n);
	if (k != 64)
		fprintf(stderr, "snprintf() returned %d in build_content()\n", k);
	memcpy(p, line_buffer, 64);
}
`)
	if len(got) != 0 {
		t.Fatalf("logging-only reuse: got %q want none", got)
	}

	// The same logging call alongside a genuine count use still reports:
	// only the format-position argument is discounted, not the function.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
void build_and_send(char *p, int s, int n) {
	char line_buffer[80];
	int k;
	k = snprintf(line_buffer, sizeof(line_buffer), "%04d\r\n", n);
	fprintf(stderr, "snprintf() returned %d\n", k);
	k = send(s, line_buffer, k, 0);
}
`)
	want3 := []string{"format=snprintf;var=k;dest=line_buffer;reuse=call_argument;guard=missing_truncation_check"}
	if strings.Join(got, "|") != strings.Join(want3, "|") {
		t.Fatalf("logging beside a count: got %q want %q", got, want3)
	}

	// The measure-then-format idiom consumes the would-be length safely by
	// construction: sizing an allocation by it and passing it back as the
	// bounded call's own size argument is not a reuse.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
char * format_pubkey(const char *privkey) {
	char *pubkey;
	int n;
	if ((n = snprintf(NULL, 0, "%s.pub", privkey)) < 0)
		return 0;
	if ((pubkey = malloc(n + 1)) == NULL)
		return 0;
	if ((n = snprintf(pubkey, n + 1, "%s.pub", privkey)) < 0)
		return 0;
	return pubkey;
}
`)
	if len(got) != 0 {
		t.Fatalf("measure-then-format: got %q want none", got)
	}

	// An error-reporting helper takes the return value in its first
	// argument slot, the position the C library reserves for the call's
	// destination or handle, so that use is not a byte count.
	got = ccFormatTruncationObs(t, `
#include <stdio.h>
int create_commit(char *msg, int msglen) {
	int err;
	err = snprintf(msg, msglen, "merge of %s\r\n", msg);
	check_lg2(err, "failed to format commit message", 0);
	return err;
}
`)
	if len(got) != 0 {
		t.Fatalf("error-helper first argument: got %q want none", got)
	}
}
