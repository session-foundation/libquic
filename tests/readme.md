# Unit tests

Each numbered test file covers one category of features or capabilities: handshakes and connection
lifecycle (`001`), sending and receiving, including `BTRequestStream` (`002`), streams (`004`),
datagrams (`007`), and so on.  The file name says what the category is.

## Adding tests

Tests added alongside a bug fix go into the existing file whose category the fix belongs to, not a
new file named after the bug.  A regression test is a test of some feature that used to be broken,
and it belongs with that feature's other tests.

Only add a new numbered file when the tests cover a category that none of the existing files does.

Test cases are named after their file's number, e.g. `TEST_CASE("004 - Stream FIN", "[004][fin][streams]")`,
and carry that number as their first tag so that `alltests "[004]"` runs the whole category.
