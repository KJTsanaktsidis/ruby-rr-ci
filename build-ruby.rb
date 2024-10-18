#!/usr/bin/env ruby

require 'bundler/inline'
gemfile do
  source 'https://rubygems.org'

  gem 'erb', '~> 4'
  gem 'fileutils', '~> 1'
  gem 'open3', '~> 0.2'
  gem 'optparse', '~> 0.5'
  gem 'pathname', '~> 0.3'
  gem 'rexml', '~> 3'
  gem 'securerandom', '~> 0.3'
  gem 'shellwords', '~> 0.2'
  gem 'timeout', '~> 0.4'
  gem 'tmpdir', '~> 0.2'

  gem 'ffi', '~> 1'
  gem 'nokogiri', '~> 1.16'
end

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

module Libc
  extend FFI::Library
  ffi_lib 'c'

  class Timespec < FFI::Struct
    layout :tv_sec, :time_t,
           :tv_nsec, :long_long
  end

  class ITimerSpec < FFI::Struct
    layout :it_interval, Timespec,
           :it_value, Timespec
  end

  CLOCK_MONOTONIC = 1
  O_NONBLOCK = 04000
  O_CLOEXEC = 02000000
  TFD_NONBLOCK = O_NONBLOCK
  TFD_CLOEXEC = O_CLOEXEC
  PIDFD_NONBLOCK = O_NONBLOCK

  # int pidfd_open(pid_t pid, unsigned int flags)
  attach_function :pidfd_open, [:pid_t, :uint], :int
  # int timerfd_create(int clockid, int flags)
  attach_function :timerfd_create, [:int, :int], :int
  # int timerfd_settime(int fd, int flags, const struct itimerspec *new_value,
  #                     struct itimrespec *old_value)
  attach_function :timerfd_settime,
                  [:int, :int, ITimerSpec.by_ref, ITimerSpec.by_ref],
                  :int
end

class RecordedCommandExecutor
  def initialize(recorder_cmdline:, test_cmdline:, env:, timeout:, cgroup_base:)
    @recorder_cmdline = recorder_cmdline
    @test_cmdline = test_cmdline
    @env = env
    @timeout = timeout
    @cgroup_base = cgroup_base
    @process_output = nil
    @pid = nil
    @status = nil
    @t_start = nil
    @duration = nil

    # Make a new cgroup to run this command in.
    @cgroup = File.join(@cgroup_base, SecureRandom.hex)
    Dir.mkdir(File.join('/sys/fs/cgroup', @cgroup))
    # Make the _test command_ run in this cgroup, but _not_ rr, by wrapping it in a call
    # to cgexec(8). That means we'll be able to kill the test on timeout, and then have rr
    # itself gracefully finish writing the trace, so the hang can be debugged.
    @full_cmdline = [*@recorder_cmdline, 'cgexec', '-g', ":#{@cgroup}", *@test_cmdline]
  end

  def cmdname = sh_get_command_string(@env, *@full_cmdline)
  def process_output = @process_output
  def pid = @pid
  def status = @status
  def duration = @duration

  def run
    raise ArgumentError, "can only run once" if @pidfd

    env_string = @env.map { "#{Shellwords.escape _1}=#{Shellwords.escape _2}" }.join(' ')
    cmdline_string = Shellwords.join @full_cmdline
    log "#{env_string} #{cmdline_string}"

    # We want combined stdout/stderr
    @t_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @pipe_r, pipe_w = IO.pipe
    @pid = Process.spawn(
      @env, *@full_cmdline,
      unsetenv_others: true, close_others: true,
      in: File::NULL, out: pipe_w, err: pipe_w
    )
    pipe_w.close
    @process_output = +""
    @pidfd = pidfd_for_pid(@pid)
    @timeout_timerfd = make_timerfd
    arm_timerfd(@timeout_timerfd, @timeout, interval: false)
    @cgpid_poll_timerfd = make_timerfd # Will be armed later
    pidfd_exited = false
    hard_kill_deadline = nil

    ios = [@pidfd, @timeout_timerfd, @cgpid_poll_timerfd, @pipe_r]
    loop do
      # We want to stop this loop when both stdout is drained and
      # the cgroup we were monitoring is empty
      break if @pipe_r.closed? && pidfd_exited && cgroup_pids.empty?
      readable, _, _ = IO.select(ios)

      if readable.include?(@pipe_r)
        data = @pipe_r.read_nonblock(4096, exception: false)
        case data
        when nil
          # EOF.
          ios.delete @pipe_r
          @pipe_r.close
        when :wait_readable
          # Loop again
        else
          @process_output << data
          print_process_output data
        end
      end

      if readable.include?(@pidfd)
        # This means the processes has exited. We will delay actually
        # reaping the child until we've drained the stdout/err though,
        # because the timeout could still fire and kill some child processes.
        ios.delete @pidfd
        pidfd_exited = true

        # But we should kill the cgroup if this happens to make sure there are no orphans.
        # We don't _expect_ this to catch anything, because rr should clean up after itself.
        kill_cgroup

        # And because we did that, we should disable the timeout and put the every-second timer
        # into ios to have it keep checking if cgroup_pids.empty? above
        arm_timerfd(@cgpid_poll_timerfd, 0.5, interval: true)
      end

      if readable.include?(@timeout_timerfd)
        # Read the timer so it stops firing.
        @timeout_timerfd.read_nonblock(8)

        # Send SIGABRT to everybod to hopefully get a nice clean Ruby stack trace of anything
        # still open. This does _not_ kill rr, which should then hopefully cleanly exit with
        # a complete trace
        pids = cgroup_pids
        log "Sending SIGABRT to #{pids.inspect} from #{@cgroup}"
        pids.each { Process.kill :SIGABRT, _1 rescue nil }

        # Now get ready to potentially kill it much harder if things didn't exit.
        arm_timerfd(@cgpid_poll_timerfd, 0.5, interval: true)
        hard_kill_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 10
      end

      if readable.include?(@cgpid_poll_timerfd)
        @cgpid_poll_timerfd.read_nonblock(8)

        # The main purpose of this timer is actually to re-check the cgroup_pids.empty?
        # condition above. But the second purpose is to decide to hard-kill if the timeout
        # expired.
        if hard_kill_deadline && hard_kill_deadline > Process.clock_gettime(Process::CLOCK_MONOTONIC)
          # Need to check again because the pids might have exited while we were blocked in IO.select
          pids = cgroup_pids
          if pids.any?
            log "Gave up waiting after 10 seconds (#{pids.size} pid(s) remain). Killing cgroup #{@cgroup}."
            kill_cgroup
          end
          hard_kill_deadline = nil
        end
      end
    end

    # Now we're in a position to actually reap the child.
    # It would be nice to do this with waitid(2) P_PIDFD to wait on the pidfd itself,
    # but it's basically impossible to map siginfo_t into Ruby with FFI, and it's not
    # actually racy to use the pid here since we know we're the parent.
    _, @status = Process.waitpid2(@pid)
  ensure
    close
  end

  private

  def close
    # unconditionally delete everything in the cgroup.
    kill_cgroup
    sleep 0.5 until cgroup_pids.empty?
    Dir.rmdir File.join("/sys/fs/cgroup", @cgroup)

    # If we hadn't reaped our process, do that.
    if !@status && @pid
      Process.kill :SIGKILL, @pid rescue nil
      _, @status = Process.waitpid2(@pid)
    end

    @duration = Process.clock_gettime(Process::CLOCK_MONOTONIC) - @t_start

    # Close all our FDs
    @pidfd&.close
    @pipe_r&.close
    @timeout_timerfd&.close
    @cgpid_poll_timerfd&.close
  end

  def pidfd_for_pid(pid)
    fd = Libc.pidfd_open(pid, Libc::PIDFD_NONBLOCK)
    raise "pidfd_open errno #{FFI.errno} pid #{pid}" if fd == -1
    IO.for_fd(fd)
  end

  def make_timerfd
    IO.for_fd(Libc.timerfd_create(
      Libc::CLOCK_MONOTONIC, Libc::TFD_NONBLOCK | Libc::TFD_CLOEXEC
    ))
  end

  def arm_timerfd(timerfd, timeout, interval: false)
    seconds = timeout.floor
    nanosecs = ((timeout - timeout.floor) * 1_000_000_000).round
    timespec = Libc::Timespec.new.tap do |t|
      t[:tv_sec] = seconds
      t[:tv_nsec] = nanosecs
    end
    itimerspec = Libc::ITimerSpec.new
    if interval
      itimerspec[:it_interval] = timespec
    else
      itimerspec[:it_value] = timespec
    end
    ret = Libc.timerfd_settime(timerfd.fileno, 0, itimerspec, nil)
    raise "timerfd_settime failed" unless ret == 0
    timerfd
  end

  def cgroup_pids
    File.read(File.join("/sys/fs/cgroup", @cgroup, "cgroup.procs")).lines.map { _1.strip.to_i }
  end

  def kill_cgroup
    File.write('1', File.join("/sys/fs/cgroup", @cgroup, "cgroup.kill"))
  end

  def log(message)
    puts "=> #{message}"
  end

  def print_process_output(text)
    $stdout.write(text)
  end
end

class JunitXMLEditor
  def initialize(doc)
    @doc = doc
  end

  def self.from_junit_data(junit_data)
    self.new(Nokogiri::XML.parse(junit_data))
  end

  def self.from_command_result(test_suite, command)
    doc = Nokogiri::XML::Document.new
    testsuites = doc.add_child('<testsuites/>')
    testsuites.add_child('<testsuite/>').tap do |el,|
      el['name'] = test_suite
      el['time'] = command.duration.to_s
      unless command.status.success?
        el.add_element('error', { 'message' => "Command exited with status #{command.status.exitstatus}" })
      end
    end

    self.new(doc)
  end

  def attach_file(attach_file)
    testsuites = @doc.xpath('//*/testsuites[1]').first 
    testsuites.add_child('<system-err/>').tap do |el, *|
      el.text = "--- ATTACHMENT #{attach_file} ---\n[[ATTACHMENT|#{File.absolute_path attach_file}]]\n"
    end
  end

  def set_test_task_name(name)
    testsuites = @doc.xpath('//*/testsuites[1]').first
    testsuites['name'] = name
  end

  def to_xml = @doc.to_xml
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

def _run_test(opts, testtask, test_file)
  # cwd is assumed to be $srcdir/build

  # relative_test_file will be something like 'bootstraptest/test_attr.rb' or 'test/zlib/test_zlib.rb'
  relative_test_file = Pathname.new(test_file).relative_path_from('..').to_s
  is_bootstraptest = relative_test_file.start_with?('bootstraptest/')
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
    *[is_bootstraptest ? nil : "--junit-filename=#{junit_xml_file}"].compact,
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
  if opts[:rr]
    recorder_cmdline = [
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
    ]
  else
    recorder_cmdline = []
  end

  if opts[:asan]
    # ASAN tests are slow!
    test_env['RUBY_TEST_TIMEOUT_SCALE'] = '5'
    test_env['SYNTAX_SUGGEST_TIMEOUT'] = '600'
  end

  executor = RecordedCommandExecutor.new(
    recorder_cmdline:, test_cmdline:, env: test_env,
    timeout: opts[:test_timeout], cgroup_base: opts[:cgroup_base]
  )
  executor.run

  junit_xml_editor = if File.exist?(junit_xml_file)
    JunitXMLEditor.from_junit_data(File.read(junit_xml_file))
  else
    JunitXMLEditor.from_command_result(relative_test_file, executor)
  end
  junit_xml_editor.set_test_task_name testtask

  if executor.status.success?
    puts "=> Test #{test_file} PASS"
  else
    puts "=> Test #{test_file} FAIL: status #{executor.status.inspect}"
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
      junit_xml_editor.attach_file trace_archive_file
      if opts[:pernosco]
        pernosco_file = File.join(test_output_dir, 'pernosco.zstd')
        sh! 'pernosco-submit', 'upload',
          '--dry-run', pernosco_file,
          '--consent-to-current-privacy-policy',
          '--build-dir', File.realpath('.'),
          '--copy-sources', File.realpath('..'),
          trace_dir, File.realpath('..')
        junit_xml_editor.attach_file pernosco_file
      end
    end
  end

  File.write(junit_xml_file, junit_xml_editor.to_xml)

  # Delete the unzipped trace dir (it's quite big)
  rm_rf trace_dir if opts[:rr]
  rm_rf File.join('/sys/fs/cgroup', cgroup) if cgroup

  return executor.status.success?
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
    raise "Cannot create sub-cgroups, timeouts will not work. Aborting."
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

