#!/usr/bin/env ruby

require 'optparse'
require 'fileutils'
require 'tmpdir'
require 'shellwords'
require 'open3'
require 'pathname'
require 'rexml'
require 'erb'

CONFIGURE_FLAGS = %w[--disable-install-doc --enable-yjit]
OPTFLAGS=%w[-O3]
DEBUGFLAGS=%w[-ggdb3 -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer]
HARDENFLAGS=%w[-U_FORTIFY_SOUCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fcf-protection=full]
CPPFLAGS=%w[-DENABLE_PATH_CHECK=0 -DRUBY_DEBUG=1 -DVM_CHECK_MODE=1]
LDFLAGS=%w[]

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
  puts "=> Cleaning source tree"
  if File.exist?('.git')
    sh! 'git', 'reset', '--hard'
    sh! 'git', 'clean', '-fxd'
  end

  puts "=> Applying patches"
  sh! 'patch', '-Np1', '-i', File.join(__dir__, 'junit_test_report.patch')

  puts "=> Building Ruby"
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
      ldflags << "-Wl,-rpath=/usr/local/asan/lib -L/usr/local/asan/lib"
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

    puts "=> Extracting bundled gems"
    sh! 'make', 'extract-gems'
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

  testopts = [
    '-v','--tty=no',
    "--junit-filename=#{junit_xml_file}",
    test_file
  ]
  test_cmdline = [
    'make', "TESTOPTS=#{Shellwords.join(testopts)}", testtask
  ]

  trace_dir = File.join(test_output_dir, 'rr_trace')
  if opts[:rr]
    test_cmdline = [
      'taskset', '-c', $WORKING_RR_CPUS.join(','),
      'rr', 'record', '--output-trace-dir', trace_dir, '--'
    ] + test_cmdline
  end

  begin
    sh!(*test_cmdline)
  rescue => e
    puts "=> Test #{test_file} FAIL: #{e}"
    result = false
    if opts[:rr]
      # On failure, pack the trace dir if we were tracing
      sh! 'rr', 'pack', trace_dir
      trace_archive_file = File.join(test_output_dir, 'rr_trace.tar.gz')
      sh! 'tar', '-cz', '-f', trace_archive_file, '-C', test_output_dir, 'rr_trace'

      # Attach it to the test output using the JUnit Attachments convention
      junit_doc = File.open(junit_xml_file, 'r') do |f|
        REXML::Document.new f
      end
      output_els = []

      fail_xpath = [
        # '*/testsuite[descendant::error]',
        # '*/testsuite[descendant::failure]',
        '*/testcase[descendant::error]',
        '*/testcase[descendant::failure]',
      ].join(' | ')
      REXML::XPath.each(junit_doc, fail_xpath) do |tc_el|
        tc_el_stderr = REXML::XPath.first(tc_el, '/system-err')
        if tc_el_stderr.nil?
          tc_el_stderr = REXML::Element.new('system-err')
          tc_el.add_element tc_el_stderr
        end
        output_els << tc_el_stderr
      end


      # The Jenkins JUnit attachment plugin wants this as an absolute path, but of course
      # we run this script in a container...
      absolute_trace_archive_file = if ENV.key?('RUBY_CHECKOUT_ABSOLUTE_PATH')
        File.join(ENV['RUBY_CHECKOUT_ABSOLUTE_PATH'], 'build', trace_archive_file)
      else
        File.absolute_path trace_archive_file
      end
      output_els.each do |el|
        el.add_text "I think I am writing to #{el.xpath}"
        el.add_text "\n\n--- RR TRACE ---\n[[ATTACHMENT|#{absolute_trace_archive_file}]]\n"
      end
      File.open(junit_xml_file, 'w') do |f|
        junit_doc.write(output: f)
      end
    end
  else
    puts "=> Test #{test_file} PASS"
  end
  # Delete the unzipped trace dir (it's quite big)
  rm_rf trace_dir if opts[:rr]

  return result
end

def do_btest(opts)
  puts "=> Running bootstrap tests"
  chdir 'build' do
    test_files = Dir.glob('../bootstraptest/**/test_*.rb')
    successes = test_files.map do |test_file|
      _run_test(opts, 'btest-ruby', test_file)
    end
    raise "One or more tests failed; see output for details" unless successes.all?
  end
end

def do_publish_build_results(opts)
  puts "=> Producing build results"
  chdir 'build' do
    failed_tests = []
    Dir.glob('test_output_dir/**/junit.xml') do |junit_file|
      junit_doc = File.open(junit_file, 'r') do |f|
        REXML::Document.new f
      end
      REXML::XPath.each(junit_doc, '*/testsuites').each do |suite_group_el|
        REXML::XPath.each(suite_group_el, '*/testsuite').each do |testsuite_el|
          did_fail = !!REXML::XPath.first(testsuite_el, '*/failure | */error')
          next unless did_fail

          failed_tests << {
            suite: suite_group_el.attribute('name'),
            file: testsuite_el.attribute('file'),
          }
        end
      end
    end

    template = File.open(File.join(__dir__, 'build_results.html.erb'), 'r') do |f|
      ERB.new(f.read)
    end
    mkdir_p 'build_results'
    File.open('build_results/index.html', 'w') do |f|
      f.write template.result_with_hash(failed_tests:)
    end
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

  opts.on('--build-results', 'Render build results') do
    options[:steps] << method(:do_publish_build_results)
  end

  opts.on('--asan', 'Enable ASAN') do
    options[:asan] = true
  end
  opts.on('--rr', 'Run tests under rr') do
    options[:rr] = true
  end
end.parse!

check_working_perf_counters! if options[:rr]
options[:steps].each { _1.call(options) }

