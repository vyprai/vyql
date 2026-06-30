package treesitter_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vyprai/vyql/extract/frontend/treesitter"
	"github.com/vyprai/vyql/extract/lowering"
	"github.com/vyprai/vyql/extract/nir"
)

func TestRubySingletonClassMethodsAreExtracted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bibliography.rb")
	src := []byte(`class Bibliography
  class << self
    def open(path, options = {})
      parse(Kernel.open(path, 'r:UTF-8').read, options)
    end
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !rubyHasFuncWithParam(prog.Modules, "open", "path") {
		t.Fatalf("singleton class method open(path) was not extracted; program=%#v", prog)
	}
}

func TestRubyModuleContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret_token.rb")
	src := []byte(`if defined?(FatFreeCRM::Application)
  if Rails.env == 'test'
    FatFreeCRM::Application.config.secret_token = '51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6'
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.module.context" {
			continue
		}
		args := n.Prop("str_args")
		for _, want := range []string{
			"lang=ruby",
			"assign:FatFreeCRM.Application.config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
			"assign:config.secret_token=51aa366864a80316a85cff0d3762347f4ae3d029d548bef034d56e82b1a2ffac5353ee6719d9b64e4354e2a0b1a901679f46a851c360a2ea377188e4b196b6b6",
			"selector:FatFreeCRM.Application.config.secret_token",
			"selector:config.secret_token",
			"expr:Rails.env=='test'",
			"literal:test",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("ruby module context missing %q; context=%q", want, args)
			}
		}
		return
	}
	t.Fatalf("analysis.module.context not found; nodes=%#v", nodes)
}

func TestRubyFunctionContextIncludesStructuredTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "library.rb")
	src := []byte(`module FFI
  module Library
    def ffi_lib(*names)
      names.each do |libname|
        begin
          FFI::DynamicLibrary.open(libname, lib_flags)
        rescue Exception => ex
          unless libname.start_with?("/") || FFI::Platform.windows?
            path = ['/usr/lib/','/usr/local/lib/'].find do |pth|
              File.exist?(pth + libname)
            end
          end
        end
      end
    end
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.function.context" || !strings.Contains(n.Prop("str_args"), "name=ffi_lib") {
			continue
		}
		args := n.Prop("str_args")
		for _, want := range []string{
			"param_name:names",
			"param_index:0",
			"call_path:FFI.DynamicLibrary.open",
			"call_path:FFI.Platform.windows?",
			"call_path:File.exist?",
			"literal:/usr/lib/",
			"literal:/usr/local/lib/",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("ruby function context missing %q; context=%q", want, args)
			}
		}
		return
	}
	t.Fatalf("analysis.function.context for ffi_lib not found; nodes=%#v", nodes)
}

func TestRubyClassContextIncludesSuperclassTokens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "base_controller.rb")
	src := []byte(`module FieldTest
  class BaseController < ActionController::Base
    protect_from_forgery
  end
end
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	prog, err := treesitter.ExtractRuby([]string{path}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.class.context" || !strings.Contains(n.Prop("str_args"), "class_name:BaseController") {
			continue
		}
		args := n.Prop("str_args")
		for _, want := range []string{
			"class_base:ActionController::Base",
			"class_base:ActionController.Base",
		} {
			if !strings.Contains(args, want) {
				t.Fatalf("ruby class context missing %q; context=%q", want, args)
			}
		}
		return
	}
	t.Fatalf("analysis.class.context for BaseController not found; nodes=%#v", nodes)
}

func TestRubyERBExtractsUnescapedHrefInterpolationObservation(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "vuln.erb")
	fixed := filepath.Join(dir, "fixed.erb")
	if err := os.WriteFile(vuln, []byte(`<% spec.authors.map do |author|
  "<a href='#{spec.homepage}'>#{author}</a>"
end.join(', ') %>
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`<% spec.authors.map do |author|
  "<a href='#{h(spec.homepage)}'>#{author}</a>"
end.join(', ') %>
<%= ("a".."z").map{|i| "<a href='#jump_#{i}'>#{i}</a>" }.join(" - ") %>
`), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractRuby([]string{vuln, fixed}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.erb.unescaped_href_interpolation" {
			continue
		}
		hits++
		args := n.Prop("str_args")
		for _, want := range []string{"template=erb", "attr=href", "expr=spec.homepage"} {
			if !strings.Contains(args, want) {
				t.Fatalf("ERB href interpolation observation missing %q; args=%q", want, args)
			}
		}
		if strings.Contains(n.Prop("loc"), "fixed.erb") {
			t.Fatalf("escaped ERB href interpolation should not emit observation: %#v", n)
		}
	}
	if hits != 1 {
		t.Fatalf("got %d ERB href interpolation observations, want 1; nodes=%#v", hits, nodes)
	}
}

func TestRubyERBExtractsHtmlEscapedUrlHrefObservation(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "vuln.erb")
	fixed := filepath.Join(dir, "fixed.erb")
	other := filepath.Join(dir, "other.erb")
	if err := os.WriteFile(vuln, []byte(`<a href="<%= escape(spec.homepage) %>">home</a>
<a href="<%= html_escape(profile_url) %>">profile</a>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`<a href="<%= homepage(spec) %>">home</a>`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte(`<a href="<%= escape(author) %>">author</a>`), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractRuby([]string{vuln, fixed, other}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for _, n := range nodes {
		if n.Type != "code.Call" || n.Prop("callee_path") != "analysis.erb.html_escaped_url_href" {
			continue
		}
		hits++
		args := n.Prop("str_args")
		for _, want := range []string{"template=erb", "attr=href", "value=url-like", "helper=html_escape"} {
			if !strings.Contains(args, want) {
				t.Fatalf("ERB URL href observation missing %q; args=%q", want, args)
			}
		}
		if strings.Contains(n.Prop("loc"), "fixed.erb") {
			t.Fatalf("URI-normalized href should not emit observation: %#v", n)
		}
		if strings.Contains(n.Prop("loc"), "other.erb") {
			t.Fatalf("non-URL href value should not emit observation: %#v", n)
		}
	}
	if hits != 2 {
		t.Fatalf("got %d URL href observations, want 2; nodes=%#v", hits, nodes)
	}
}

func TestRubySemanticReviewTokens(t *testing.T) {
	dir := t.TempDir()
	vuln := filepath.Join(dir, "vuln.rb")
	fixed := filepath.Join(dir, "fixed.rb")
	if err := os.WriteFile(vuln, []byte(`
class Users < Application
  before :authenticate_every
  def update
    Chef::WebUIUser.cdb_load(params[:id])
    @user.cdb_save
    @user.cdb_destroy
  end
end

class HomeController < ActionController::Base
  def job
    job = params[:job]
    enable = params[:enable]
    ClockworkWeb.enable(job)
    ClockworkWeb.disable(job)
  end
end

def cama_comments_render_html(comment)
  "<div>#{comment.content}</div>"
end

def create
  User.find_by(params[:user])
end

def request
  datum = response(datum)
  reset if datum[:persistent]
end

def initialize(image_path, colors=16, depth=8)
  `+"`"+`convert #{image_path} -colors #{colors} -depth #{depth} histogram:info:-`+"`"+`
end

def diff
  if WINDOWS
    cmd = sprintf '"%s" %s %s', diff_bin, diff_options.join(' '), @paths.map { |s| %("#{s}") }.join(' ')
    out = `+"`"+`#{cmd}`+"`"+`
  end
end

def report_post_edits(report)
  builder = DB.build <<~SQL
  FROM post_revisions pr
  JOIN posts p ON p.id = pr.post_id
  SQL
  report.data << revision
end

def url_path
  url = "?queues=#{@queues.join(",")}"
end

def legal?(string)
  string.to_s =~ /^[0-9a-f]{24}$/i
end

def build_ssl_context
  OpenSSL::SSL::SSLContext.new.tap do |context|
    context.ca_file = @config.server_ca_cert
  end
end

def fill_field(model, params)
  model.send("#{polymorphic_as}_type=", params["#{polymorphic_as}_type"])
end

def postpone_email_change_until_confirmation_and_regenerate_confirmation_token
  self.unconfirmed_email = self.email
  self.email = self.devise_email_in_database
  self.confirmation_token = nil
  generate_confirmation_token
end
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixed, []byte(`
class Users < Application
  before :is_admin
  def update
    Chef::WebUIUser.cdb_load(params[:id])
    @user.cdb_save
    @user.cdb_destroy
  end
end

class HomeController < ActionController::Base
  protect_from_forgery with: :exception
  def job
    job = params[:job]
    enable = params[:enable]
    ClockworkWeb.enable(job)
    ClockworkWeb.disable(job)
  end
end

def cama_comments_render_html(comment)
  sanitize comment.content
end

def create
  User.find_by(email: params[:user][:email])
end

def request
  @persistent_socket_reusable = true
  datum = response(datum)
  reset if datum[:persistent]
end

def initialize(image_path, colors=16, depth=8)
  `+"`"+`convert #{image_path.shellescape} -colors #{colors.to_i} -depth #{depth.to_i} histogram:info:-`+"`"+`
end

def diff
  Open3.capture3(diff_bin, *(diff_options + @paths))
end

def report_post_edits(report)
  builder = DB.build <<~SQL
  FROM post_revisions pr
  JOIN posts p ON p.id = pr.post_id
  SQL
  builder.where("t.archetype != ?", Archetype.private_message)
  builder.secure_category(ids)
  report.data << revision
end

def url_path
  url = "?queues=#{CGI.escape(@queues.join(","))}"
end

def legal?(string)
  string.to_s =~ /\A[0-9a-f]{24}\z/i
end

def build_ssl_context
  OpenSSL::SSL::SSLContext.new.tap do |context|
    context.ca_file = @config.server_ca_cert
    context.verify_mode = OpenSSL::SSL::VERIFY_PEER
  end
end

def fill_field(model, params)
  valid_model_class = valid_polymorphic_class params["#{polymorphic_as}_type"]
  model.send("#{polymorphic_as}_type=", valid_model_class)
end

def postpone_email_change_until_confirmation_and_regenerate_confirmation_token
  devise_unconfirmed_email_will_change!
  self.unconfirmed_email = self.email
  self.email = self.devise_email_in_database
  self.confirmation_token = nil
  generate_confirmation_token
end
`), 0o600); err != nil {
		t.Fatal(err)
	}

	prog, err := treesitter.ExtractRuby([]string{vuln, fixed}, dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := lowering.Lower(prog, true)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := g.AllNodes()
	if err != nil {
		t.Fatal(err)
	}
	vulnArgs := ""
	for _, n := range nodes {
		if n.Type != "code.Call" || !strings.HasPrefix(n.Prop("callee_path"), "analysis.") {
			continue
		}
		if strings.Contains(n.Prop("loc"), "fixed.rb") && strings.Contains(n.Prop("str_args"), "ruby_review:") {
			t.Fatalf("fixed Ruby context emitted review fact: loc=%s args=%q", n.Prop("loc"), n.Prop("str_args"))
		}
		if strings.Contains(n.Prop("loc"), "vuln.rb") {
			vulnArgs += "\x00" + n.Prop("str_args")
		}
	}
	for _, want := range []string{
		"ruby_review:stored_html_interpolation_missing_sanitize",
		"ruby_review:active_record_find_by_request_hash",
		"ruby_review:chef_user_management_missing_admin_guard",
		"ruby_review:persistent_response_reuse_missing_guard",
		"ruby_review:clockwork_job_csrf_missing_forgery_protection",
		"ruby_review:imagemagick_convert_backtick_unescaped_interpolation",
		"ruby_review:windows_backtick_diff_command_unescaped",
		"ruby_review:post_edit_report_missing_private_filters",
		"ruby_review:unescaped_query_string_join_interpolation",
		"ruby_review:ruby_line_anchor_hex_validation",
		"ruby_review:tls_ca_file_without_verify_mode",
		"ruby_review:polymorphic_type_selected_from_params",
		"ruby_review:devise_reconfirmation_missing_dirty_tracking",
	} {
		if !strings.Contains(vulnArgs, want) {
			t.Fatalf("vulnerable Ruby context missing %q; args=%q", want, vulnArgs)
		}
	}
}

func rubyHasFuncWithParam(mods []nir.Module, name, param string) bool {
	var walk func([]nir.Stmt) bool
	walk = func(stmts []nir.Stmt) bool {
		for _, st := range stmts {
			switch x := st.(type) {
			case nir.FuncDef:
				if x.Name == name {
					for _, p := range x.Params {
						if p == param {
							return true
						}
					}
				}
				if walk(x.Body) {
					return true
				}
			case nir.ClassDef:
				if walk(x.Body) {
					return true
				}
			case nir.Block:
				if walk(x.Stmts) {
					return true
				}
			}
		}
		return false
	}
	for _, mod := range mods {
		if walk(mod.Body) {
			return true
		}
	}
	return false
}
