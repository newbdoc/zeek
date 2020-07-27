# @TEST-EXEC: zeek -b %INPUT >out
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	print "Justification (input string 'abc')";
	print "----------------------------------";
	local s1 : string = "abc";
	print fmt("ljust: '%s'", ljust(s1, 2, " "));   # 'abc'
	print fmt("ljust: '%s'", ljust(s1, 3, " "));   # 'abc'
	print fmt("ljust: '%s'", ljust(s1, 5));        # 'abc  '
	print fmt("ljust: '%s'", ljust(s1, 5, "-"));   # 'abc--'
	print fmt("ljust: '%s'", ljust(s1, 2, "--"));  # This should return an error
	print fmt("rjust: '%s'", rjust(s1, 2, " "));   # 'abc'
	print fmt("rjust: '%s'", rjust(s1, 3, " "));   # 'abc'
	print fmt("rjust: '%s'", rjust(s1, 5));        # '  abc'
	print fmt("rjust: '%s'", rjust(s1, 5, "-"));   # '--abc'
	print fmt("rjust: '%s'", rjust(s1, 2, "--"));  # This should return an error
	print fmt("zfill: '%s'", zfill(s1, 2));        # 'abc'
	print fmt("zfill: '%s'", zfill(s1, 3));        # 'abc'
	print fmt("zfill: '%s'", zfill(s1, 5));        # '00abc'
	print "";

	print "Content checking";
	print "----------------";
	print fmt("isnum abc   : %d", isnum("abc"));
	print fmt("isnum 123   : %d", isnum("123"));
	print fmt("isalpha ab  : %d", isalpha("ab"));
	print fmt("isalpha 1a  : %d", isalpha("1a"));
	print fmt("isalpha a1  : %d", isalpha("a1"));
	print fmt("isalnum ab  : %d", isalnum("ab"));
	print fmt("isalnum 1a  : %d", isalnum("1a"));
	print fmt("isalnum a1  : %d", isalnum("a1"));
	print fmt("isalnum 12  : %d", isalnum("12"));
	print fmt("isalnum ##12: %d", isalnum("##12"));
	print "";

	print "String counting (input str 'aabbaa')";
	print "------------------------------------";
	local s2 : string = "aabbaa";
	print fmt("count_substr aa: %d", count_substr(s2, "aa"));
	print fmt("count_substr bb: %d", count_substr(s2, "bb"));
	print fmt("count_substr cc: %d", count_substr(s2, "cc"));
	print "";

	print "Starts/endswith";
	print "---------------";
	local s3: string = "abcdefghi";
	print fmt("startswith bro: %d", startswith(s3, "abc"));
	print fmt("startswith ids: %d", startswith(s3, "ghi"));
	print fmt("endswith ids: %d", endswith(s3, "ghi"));
	print fmt("endswith bro: %d", endswith(s3, "abc"));
	print "";

	print "Transformations";
	print "---------------";
	print fmt("swapcase 'aBc': %s", swapcase("aBc"));
	print fmt("to_title 'bro is a very neat ids': '%s'", to_title("bro is a very neat ids"));
	print fmt("to_title '   ': '%s'", to_title("   "));
	print fmt("to_title '  a   c  ': '%s'", to_title("  a   c  "));
	print fmt("removeprefix 'ananab'/'an' : %s", removeprefix("ananab", "an"));
	print fmt("removeprefix 'anatnab'/'an': %s", removeprefix("anatnab", "an"));
	print fmt("removesuffix 'banana'/'na' : %s", removesuffix("banana", "na"));
	print fmt("removesuffix 'bantana'/'na': %s", removesuffix("bantana", "na"));
	print "";

	print fmt("find_str/rfind_str (input string '%s')", s3);
	print "-----------------------------------------------------";
	print fmt("find_str: %d", find_str(s3, "abcd"));
	print fmt("find_str: %d", find_str(s3, "abcd", 1));
	print fmt("find_str: %d", find_str(s3, "abcd", 0, 2));
	print fmt("find_str: %d", find_str(s3, "efg"));
	print fmt("find_str: %d", find_str(s3, "efg", 2, 6));
	print fmt("find_str: %d", find_str(s3, "efg", 6, 2));
	print fmt("find_str: %d", rfind_str(s3, "abcd"));
	print fmt("find_str: %d", rfind_str(s3, "abcd", 1));
	print fmt("find_str: %d", rfind_str(s3, "abcd", 0, 2));
	print fmt("find_str: %d", rfind_str(s3, "efg"));
	print fmt("find_str: %d", rfind_str(s3, "efg", 2, 6));
	print fmt("find_str: %d", rfind_str(s3, "efg", 6, 2));
	print "";
	}
