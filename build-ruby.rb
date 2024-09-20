#!/usr/bin/env ruby

require 'optparse'
require 'fileutils'
require 'tmpdir'
require 'shellwords'
require 'open3'
require 'pathname'
require 'rexml'
require 'erb'
require 'securerandom'
require 'timeout'
require 'fiddle'

$stdout.sync = true
CONFIGURE_FLAGS = %w[--disable-install-doc --enable-yjit]
OPTFLAGS=%w[-O3]
DEBUGFLAGS=%w[-ggdb3 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer]
HARDENFLAGS=%w[-U_FORTIFY_SOUCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full]
CPPFLAGS=%w[-DENABLE_PATH_CHECK=0 -DRUBY_DEBUG=1 -DVM_CHECK_MODE=1]
LDFLAGS=%w[]
TESTS_WITHOUT_SYSCALLBUF = [
  'test/ruby/test_require.rb'
].freeze
ALLOWED_ENV_VARS = %w[
  LANG PATH USER LOGNAME HOME SHELL INVOCATION_ID TERM XDG_SESSION_ID XDG_RUNTIME_DIR
  XDG_SESSION_TYPE XDG_SESSION_CLASS DBUS_SESSION_BUS_ADDRESS
].freeze

include FileUtils::Verbose
@fileutils_label = "==> "

FIDDLE_LIBC = Fiddle.dlopen(nil)
FIDDLE_PIDFD_OPEN_BINDING = Fiddle::Function.new(
  FIDDLE_LIBC['pidfd_open'],
  [Fiddle::TYPE_INT, Fiddle::TYPE_UINT], # input: pid_t pid, unsigned int flags
  Fiddle::TYPE_INT # output: int fd
)

PIDFD_NONBLOCK = 04000
def pidfd_open(pid, flags = 0)
  raw_fd = FIDDLE_PIDFD_OPEN_BINDING.call(pid, flags)
  raise "pidfd_open failed: #{raw_fd}" if raw_fd < 0
  IO.for_fd(raw_fd)
end

def sh_get_command_string(*args)
  cmd = args
  env = {}
  env = cmd.shift if cmd.first.is_a?(Hash)

  env_str = env.map { |k, v| "#{Shellwords.escape(k)}=#{Shellwords.escape(v)}" }
  cmd_str = Shellwords.join(cmd)

  [(env.any? ? env_str : nil), cmd_str].compact.join(' ')
end


def sh!(*args, **kwargs)
  fu_output_message sh_get_command_string(*args)
  system(*args, **kwargs, exception: true) 
  $!
end

def sh_with_timeout!(*args, timeout: nil, on_timeout: nil, **kwargs)
  return sh!(*args, **kwargs) unless timeout && on_timeout

  cmdname = sh_get_command_string(*args)
  fu_output_message cmdname
  pid = Process.spawn(*args, **kwargs)
  pidfd = pidfd_open(pid, PIDFD_NONBLOCK)

  # Wait for the process to be finished, or for the timeout.
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
  loop do
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    wait_for = 0
    if deadline && now >= deadline
      puts "=> Command #{cmdname} timeout #{timeout} seconds exceeded."
      on_timeout.call(pid)
      deadline = nil
    elsif deadline
      wait_for = deadline - now
    end
    readable, _, _ = IO.select([pidfd], [], [], wait_for)
    break if readable&.include?(pidfd)
  end
  _, status = Process.waitpid2(pid)
  raise "Command #{cmdname} failed: #{status.inspect}" unless status.success?
  status
ensure
  pidfd&.close
end

def sh(*args, **kwargs)
  fu_output_message Shellwords.join(args)
  system(*args, **kwargs)
  $!
end

def sh_capture!(*args, **kwargs)
  fu_output_message Shellwords.join(args)
  output, status = Open3.capture2(*args, **kwargs)
  raise "Process exited with #{status.inspect}" unless status.success?
  output
end

def do_build(opts)
  puts "=> Cleaning source tree"
  if File.exist?('.git')
    sh! 'git', 'reset', '--hard'
    sh! 'git', 'clean', '-fxd'
  end

  puts "=> Applying patches"
  Dir.glob(File.join(__dir__, 'ruby_patches/*.patch')).each do |patch|
    sh! 'patch', '-Np1', '-i', patch
  end

  puts "=> Building Ruby"
  sh! "./autogen.sh"
  rm_rf 'build'
  mkdir 'build'
  chdir 'build' do
    hardenflags = HARDENFLAGS.dup
    debugflags = DEBUGFLAGS.dup
    ldflags = LDFLAGS.dup
    configure_flags = CONFIGURE_FLAGS.dup
    cppflags = CPPFLAGS.dup
    if opts[:asan]
      debugflags << "-fsanitize=address"
      ldflags << "-Wl,-rpath=/usr/local/asan/lib -L/usr/local/asan/lib"
      configure_flags << "CC=clang"
      cppflags << "-DUSE_MN_THREADS=0"
    end
    sh! '../configure', *configure_flags,
      "optflags=#{OPTFLAGS.join(' ')}",
      "debugflags=#{debugflags.join(' ')}",
      "hardenflags=#{hardenflags.join(' ')}",
      "cppflags=#{cppflags.join(' ')}",
      "LDFLAGS=#{ldflags.join(' ')}"
    sh! 'make', '-j'

    puts "=> Extracting bundled gems"
    sh! 'make', 'extract-gems'
  end
end

def _attach_trace_to_test(junit_xml_file, trace_archive_file)
  junit_doc = File.open(junit_xml_file, 'r') do |f|
    REXML::Document.new f
  end
  output_els = []

  fail_xpath = [
    '//*/testsuite[descendant::error]',
    '//*/testsuite[descendant::failure]',
    '//*/testcase[descendant::error]',
    '//*/testcase[descendant::failure]',
  ].join(' | ')
  REXML::XPath.each(junit_doc, fail_xpath) do |tc_el|
    tc_el_stderr = REXML::XPath.first(tc_el, '/system-err')
    if tc_el_stderr.nil?
      tc_el_stderr = REXML::Element.new('system-err')
      tc_el.add_element tc_el_stderr
    end
    output_els << tc_el_stderr
  end

  output_els.each do |el|
    # Two things;
    #   - The Jenkins JUnit attachment plugin wants this as an absolute path. The container we run in
    #     maps the workspace directory to the same path on the host and container, so this works.
    #   - Important that each stderr is unique, otherwise the jenkins test reporting machinery coalesces
    #     them together. So add the xpath of the element to it.
    el.add_text "\n\n--- RR TRACE ---\n#{el.xpath}\n[[ATTACHMENT|#{File.absolute_path trace_archive_file}]]\n"
  end
  File.open(junit_xml_file, 'w') do |f|
    junit_doc.write(output: f)
  end
end

def _run_test(opts, testtask, test_file)
  # cwd is assumed to be $srcdir/build

  result = true

  # relative_test_file will be something like 'bootstraptest/test_attr.rb' or 'test/zlib/test_zlib.rb'
  relative_test_file = Pathname.new(test_file).relative_path_from('..').to_s
  # full_test_name will be something like 'test_zlib_test_zlib'
  full_test_name = relative_test_file.gsub('/', '__').gsub(/\.rb$/, '')
  # test_output_dir will be test_results/$full_test_name
  test_output_dir = File.join('test_output_dir', full_test_name)
  junit_xml_file = File.join(test_output_dir, 'junit.xml')

  rm_rf test_output_dir
  mkdir_p test_output_dir

  # We need to run with a _whitelist_ of environment variables, so a ton of jenkins stuff
  # (including credentials :/) don't leak into the recording.
  test_env = ENV.slice(*ALLOWED_ENV_VARS)

  testopts = [
    '-v','--tty=no',
    "--junit-filename=#{junit_xml_file}",
    "--junit-suite-group-name=#{testtask}",
    test_file
  ]
  test_cmdline = [
    'make',
    "TESTOPTS=#{Shellwords.join(testopts)}",
    "PRECHECK_TEST_ALL=",
    "SHOWFLAGS=",
    testtask
  ]


  trace_dir = File.join(test_output_dir, 'rr_trace')
  cgroup = nil
  on_rr_timeout = nil
  if opts[:cgroup_base]
    cgroup = File.join(opts[:cgroup_base], SecureRandom.hex)
    Dir.mkdir(File.join('/sys/fs/cgroup', cgroup))
    test_cmdline = ['cgexec', '-g', ":#{cgroup}"] + test_cmdline
    on_rr_timeout = ->(pid) do
      # Send SIGABRT to everything in the control group to give RR a few seconds to tidy everything up.
      pids = File.read(File.join("/sys/fs/cgroup", cgroup, "cgroup.procs")).lines.map { _1.strip.to_i }
      puts "=> Sending SIGABRT to #{pids.inspect} from #{cgroup}"
      pids.each { Process.kill :SIGABRT, _1 rescue nil }
      10.times do
        pids = File.read(File.join("/sys/fs/cgroup", cgroup, "cgroup.procs")).lines.map { _1.strip.to_i }
        break if pids.empty?
        puts "=> (still waiting for #{pids.inspect} to exit"
        sleep 1
      end
      puts "=> Killing cgroup #{cgroup}"
      File.write('1', File.join("/sys/fs/cgroup", cgroup, "cgroup.kill"))
      # That should make evertying shut down now.
    end
  end
  if opts[:rr]
    test_cmdline = [
      'taskset', '-c', $WORKING_RR_CPUS.join(','),
      'rr', 'record', '--output-trace-dir', trace_dir,
      *[opts[:chaos] ? '--chaos' : nil].compact,
      # Some tests do things that break RR's in-process sycall accelerator thingy
      # (e.g. deliberately exhaust all the FDs); run these tests in slowpoke mode
      # with --no-syscall-buffer.
      *[TESTS_WITHOUT_SYSCALLBUF.include?(relative_test_file) ? '--no-syscall-buffer' : nil].compact,
      '--wait', '--disable-avx-512',
      # These are from running `rr cpufeatures` on... _my_ CPU (Tiger Lake, i7-1165G7).
      # Are they a good set of defaults? Who knows.
      '--disable-cpuid-features', '0x80050440,0x40140400',
      '--disable-cpuid-features-ext', '0xc405814,0xe73fa021,0x3eff8ef',
      '--disable-cpuid-features-xsave', '0xfffffff0',
      '--'
    ] + test_cmdline
  end

  if opts[:asan]
    # ASAN tests are slow!
    test_env['RUBY_TEST_TIMEOUT_SCALE'] = '5'
    test_env['SYNTAX_SUGGEST_TIMEOUT'] = '600'
  end

  begin
    sh_with_timeout!(
      test_env, *test_cmdline,
      timeout: opts[:test_timeout], on_timeout: on_rr_timeout,
      unsetenv_others: true
    )
  rescue => e
    puts "=> Test #{test_file} FAIL: #{e}"
    result = false
    if opts[:rr]
      # On failure, pack the trace dir if we were tracing
      sh! 'rr', 'pack', trace_dir
      if opts[:pernosco]
        binaries = ['ruby', 'miniruby']
        binaries.concat Dir.glob('*.so')
        binaries.concat Dir.glob('/.ext/**/*.so')
        sh! 'pernosco-submit', 'analyze-build', "--build-dir", File.realpath('.'),
          '--allow-source', '/usr/include',
          '--allow-source', '/usr/lib',
          '--allow-source', '/usr/local/include',
          '--allow-source', '/usr/local/lib',
          '--copy-sources', '..', trace_dir, *binaries
      end
      trace_archive_file = File.join(test_output_dir, 'rr_trace.tar.gz')
      sh! 'tar', '-cz', '-f', trace_archive_file, '-C', test_output_dir, 'rr_trace'
      # Attach it to the test output using the JUnit Attachments convention
      begin
        _attach_trace_to_test junit_xml_file, trace_archive_file
      rescue => innerex
        puts "==> Attaching trace to test failed"
        puts innerex.inspect
        puts innerex.backtrace.join("\n")
      end
      if opts[:pernosco]
        pernosco_file = File.join(test_output_dir, 'pernosco.zstd')
        sh! 'pernosco-submit', 'upload',
          '--dry-run', pernosco_file,
          '--consent-to-current-privacy-policy',
          '--build-dir', File.realpath('.'),
          '--copy-sources', File.realpath('..'),
          trace_dir, File.realpath('..')
        _attach_trace_to_test junit_xml_file, pernosco_file
      end
    end
  else
    puts "=> Test #{test_file} PASS"
  end
  # Delete the unzipped trace dir (it's quite big)
  rm_rf trace_dir if opts[:rr]
  rm_rf File.join('/sys/fs/cgroup', cgroup) if cgroup

  return result
end

def do_btest(opts)
  puts "=> Running btest suite"
  chdir 'build' do
    test_files = Dir.glob('../bootstraptest/**/test_*.rb')
    successes = test_files.map do |test_file|
      _run_test(opts, 'btest-ruby', test_file)
    end
    raise "One or more tests failed; see output for details" unless successes.all?
  end
end

def do_test_tool(opts)
  puts "=> Running test-tool suite"
  chdir 'build' do
    test_files = Dir.glob('../tool/test/**/test_*.rb')
    successes = test_files.map do |test_file|
      _run_test(opts, 'test-tool', test_file)
    end
    raise "One or more tests failed; see output for details" unless successes.all?
  end
end

def do_test_all(opts)
  puts "=> Running test-allsuite"
  chdir 'build' do
    test_files = Dir.glob('../test/**/test_*.rb')
    successes = test_files.map do |test_file|
      _run_test(opts, 'test-all', test_file)
    end
    raise "One or more tests failed; see output for details" unless successes.all?
  end
end


def check_working_perf_counters!
  puts "=> Checking which CPUs have working perf counters"
  cpu_csv = sh_capture!('lscpu', '--all', '--parse')
  cpu_lines = cpu_csv.lines.grep_v(/^\#/).map(&:strip).map { _1.split(',') }
  cpu_numbers = cpu_lines.map { _1[0].to_i }
  $WORKING_RR_CPUS = cpu_numbers.select do |cpu|
    Dir.mktmpdir do |tracedir|
      _, _, status = Open3.capture3(
        'rr', 'record', '--bind-to-cpu', cpu.to_s, '--output-trace-dir', File.join(tracedir, 'trace'), 'true'
      )
      status.success?
    end
  end
  if $WORKING_RR_CPUS.empty?
    puts "=> No CPUs appear to have working perf counters."
    puts "=> rr output is as follows:"
    sh! 'rr', 'record', 'true'
  end
  puts "=> CPUs #{$WORKING_RR_CPUS.join(', ')} have working perf counters"
end

def check_can_make_cgroup!(opts)
  # This won't work with non-unified cgroups, but I don't care.
  self_cgroup = File.read('/proc/self/cgroup').lines.map { _1.strip.split(':').last }.first || ''
  full_cgroup_path = File.join('/sys/fs/cgroup', self_cgroup)
  if File.writable? full_cgroup_path
    puts "=> Own cgroup hierarchy #{self_cgroup}"
    opts[:cgroup_base] = self_cgroup
  else
    puts "=> Warning: Cannot create sub-cgroups, timeouts will not work."
  end
end

options = {
  steps: [],
  asan: false,
  rr: false,
  pernosco: false,
  chaos: false,
  cgroup_base: nil,
  test_timeout: 60 * 30
}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby_build.rb --build | --btest | --test | --spec"

  opts.on('--build', 'Run the build') do
    options[:steps] << method(:do_build)
  end

  opts.on('--btest', 'Run btest suite') do
    options[:steps] << method(:do_btest)
  end

  opts.on('--test-tool', 'Run test-tool suite') do
    options[:steps] << method(:do_test_tool)
  end

  opts.on('--test-all', 'Run test-all suite') do
    options[:steps] << method(:do_test_all)
  end

  opts.on('--asan', 'Enable ASAN') do
    options[:asan] = true
  end
  opts.on('--rr', 'Run tests under rr') do
    options[:rr] = true
  end
  opts.on('--pernosco', 'Produce a pernosco archive of failed tests') do
    options[:pernosco] = true
  end
  opts.on('--chaos', 'Run tests under rr chaos mode') do
    options[:chaos] = true
  end
  opts.on('--test-timeout=TIMEOUT', 'Time out individual test file runs (sconds)') do |timeout|
    options[:test_timeout] = timeout.to_i
  end
end.parse!

check_working_perf_counters! if options[:rr]
check_can_make_cgroup!(options)
options[:steps].each { _1.call(options) }

