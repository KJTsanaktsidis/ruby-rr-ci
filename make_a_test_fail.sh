#!/bin/bash
# echo "assert_equal 'ok', %q{puts 'fail'}" >> ruby/bootstraptest/test_attr.rb
pushd ruby;
patch -Np1 <<PATCHFILE
diff --git a/test/ostruct/test_ostruct.rb b/test/ostruct/test_ostruct.rb
index 19bb606145..af23867612 100644
--- a/test/ostruct/test_ostruct.rb
+++ b/test/ostruct/test_ostruct.rb
@@ -128,6 +128,7 @@ def test_getter
     os.foo = :bar
     assert_equal :bar, os[:foo]
     assert_equal :bar, os['foo']
+    assert_equal :yeet, os[:foo]
   end

   def test_dig
PATCHFILE
popd;
