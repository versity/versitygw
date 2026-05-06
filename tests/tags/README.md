# Tag Program Examples

To find specific tests, based on function, header, etc., tags are included in the test suite.  Run these examples from the root repo folder

List all tag descriptions:
```
./tests/tags/get_tests.sh --list-tags
```

List description for a specific tag:
```
./test/tags/get_tests.sh --list-tags <tag name>
```

List all tests matching a tag:
```
./tests/tags/get_tests.sh --list <tag name>
```

List all tests matching all of the tags:
```
./tests/tags/get_tests.sh --list <tag name>,<tag name>
```

List all tests matching any of the tags:
```
./tests/tags/get_tests.sh --any <tag name>,<tag name>
```

Run all tests matching a tag:
```
VERSITYGW_TEST_ENV=tests/<env file> ./tests/tags/get_tests.sh --run <tag name>
```