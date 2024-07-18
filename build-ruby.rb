#!/usr/bin/env ruby

require 'optparse'
require 'fileutils'
require 'tmpdir'
require 'shellwords'
require 'open3'
require 'pathname'

CONFIGURE_FLAGS = %w[--disable-install-doc --enable-yjit]
OPTFLAGS=%w[-O3]
DEBUGFLAGS=%w[-ggdb3 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer]
HARDENFLAGS=%w[-U_FORTIFY_SOUCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full]
CPPFLAGS=%w[-DENABLE_PATH_CHECK=0 -DRUBY_DEBUG=1 -DVM_CHECK_MODE=1]
LDFLAGS=%w[]
ENV['PATH'] = "/opt/asan-dist/bin:#{ENV['PATH']}"

include FileUtils::Verbose
@fileutils_label = "==> "

def sh!(*args, **kwargs)
  fu_output_message Shellwords.join(args)
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

def do_build(opts)
  puts "=> Building Ruby"
  if File.exist?('.git')
    sh! 'git', 'reset', '--hard'
    sh! 'git', 'clean', '-fxd'
  end
  sh! "./autogen.sh"
  rm_rf 'build'
  mkdir 'build'
  chdir 'build' do
    hardenflags = HARDENFLAGS.dup
    ldflags = LDFLAGS.dup
    configure_flags = CONFIGURE_FLAGS.dup
    cppflags = CPPFLAGS.dup
    if opts[:asan]
      hardenflags << "-fsanitize=address"
      ldflags << "-Wl,-rpath=/opt/asan-dist/lib"
      configure_flags << "CC=clang"
      cppflags << "-DUSE_MN_THREADS=0"
    end
    sh! '../configure', *configure_flags,
      "optflags=#{OPTFLAGS.join(' ')}",
      "debugflags=#{DEBUGFLAGS.join(' ')}",
      "hardenflags=#{hardenflags.join(' ')}",
      "cppflags=#{cppflags.join(' ')}",
      "LDFLAGS=#{ldflags.join(' ')}"
    sh! 'make', '-j'
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

  rm_rf test_output_dir
  mkdir_p test_output_dir

  testopts = [
    '-v','--tty=no',
    "--launchable-test-reports=#{File.join(test_output_dir, 'launchable.json')}",
    test_file
  ]
  test_cmdline = [
    'make', "TESTOPTS=#{Shellwords.join(testopts)}", testtask
  ]

  trace_dir = File.join(test_output_dir, 'rr_trace')
  if opts[:rr]
    test_cmdline = [
      '/opt/asan-dist/bin/rr', 'record', '--output-trace-dir', trace_dir, '--'
    ] + test_cmdline
  end

  begin
    sh! *test_cmdline
  rescue
    success = false
    # On failure, pack the trace dir if we were tracing
    sh! '/opt/asan-dist/bin/rr', 'pack', trace_dir if opts[:rr]
    sh! 'tar', '-czv', '-f', File.join(test_output_dir, 'rr_trace.tar.gz'), '-C', test_output_dir, 'rr_trace'
  end
  # Delete the unzipped trace dir (it's quite big)
  rm_rf trace_dir if opts[:rr]

  puts "=> Test #{test_file} #{success ? 'PASS' : 'FAIL'}"
  return success
end

def do_btest(opts)
  puts "=> Running bootstrap tests"
  chdir 'build' do
    test_files = Dir.glob('../bootstraptest/**/test_*.rb')
    successes = test_files.map do |test_file|
      _run_test(opts, 'btest', test_file)
    end
    raise "One or more tests failed; see output for details" unless successes.all?
  end
end

options = {
  steps: [],
  asan: false,
  rr: false,
}
OptionParser.new do |opts|
  opts.banner = "Usage: ruby_build.rb --build | --btest | --test | --spec"

  opts.on('--build', 'Run the build') do
    options[:steps] << method(:do_build)
  end

  opts.on('--btest', 'Run bootstrap tests') do
    options[:steps] << method(:do_btest)
  end

  opts.on('--asan', 'Enable ASAN') do
    options[:asan] = true
  end
  opts.on('--rr', 'Run tests under rr') do
    options[:rr] = true
  end
end.parse!

options[:steps].each { _1.call(options) }

