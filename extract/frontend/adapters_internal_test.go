package frontend

import "testing"

func TestConstraintAllows(t *testing.T) {
	cases := []struct {
		constraint, recvType string
		want                 bool
	}{
		{"sql.DB", "sql.DB", true},
		{"sql.DB", "redis.Client", false},
		{"sql.DB,sqlx.DB,gorm.DB", "gorm.DB", true},
		{"sql.DB,sqlx.DB,gorm.DB", "mongo.Database", false},
		{"sql.DB", "", false}, // empty recv handled by the caller, not here
	}
	for _, c := range cases {
		if got := constraintAllows(c.constraint, c.recvType); got != c.want {
			t.Errorf("constraintAllows(%q,%q)=%v want %v", c.constraint, c.recvType, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	// prefix mode: exact, dotted, subscript continuations
	if !matchPath("request.form", []string{"request.form"}, "prefix") {
		t.Error("exact prefix should match")
	}
	if !matchPath("request.form.get", []string{"request.form"}, "prefix") {
		t.Error("dotted continuation should match")
	}
	if matchPath("request.formdata", []string{"request.form"}, "prefix") {
		t.Error("a longer word should NOT prefix-match (request.formdata != request.form.)")
	}
	// contains mode: substring anywhere (Go varying receivers)
	if !matchPath("r.URL.Query.Get", []string{".URL.Query"}, "contains") {
		t.Error("contains should match a mid-path substring")
	}
	if matchPath("db.Query", []string{".URL.Query"}, "contains") {
		t.Error("contains should not falsely match an unrelated path")
	}
}
