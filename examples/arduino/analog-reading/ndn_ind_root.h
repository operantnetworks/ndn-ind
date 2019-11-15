#define STR1(x) #x
#define STR2(x) STR1(x)
#define CONCAT(x, y) x ## y

// This makes a string for #include from the NDN-IND root directory.
// It should include the absolute path up to ndn-ind, except put "ndn-c"
// instead of "ndn-ind". Use it like this:
// #include NDN_IND_ROOT(pp/c/name.c)
// We split "ndn-ind" into "ndn-c" and "pp" because the Arduino compiler won't
// accept NDN_IND_SRC(/src/c/name.c) with a starting slash.
// We have to use an absolute path because the Arduino compiler won't
// include a relative file.
#define NDN_IND_ROOT(x) STR2(CONCAT(/please/fix/NDN_IND_ROOT/in/ndn_cpp_root.h/ndn-c, x))

