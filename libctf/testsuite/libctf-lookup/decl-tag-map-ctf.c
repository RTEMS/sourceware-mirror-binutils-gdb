int foo __attribute__((btf_decl_tag("dtag"))) __attribute__((used));

int multi __attribute__((btf_decl_tag("multi1")))
	  __attribute__((btf_decl_tag("multi2")))
	  __attribute__((btf_decl_tag("multi3")))
	  __attribute__((used));

struct
{
  char a;
  char b __attribute__((btf_decl_tag("dtag2")));
} bar __attribute__((used));

struct
{
  int c;
  int d;
} baz __attribute__((btf_decl_tag("dtag3"))) __attribute__((used));

struct
{
  int e __attribute__((btf_decl_tag("dtag_inner")));
  int f;
} qux __attribute__((btf_decl_tag("dtag4_outer"))) __attribute__((used));

int __attribute__((btf_decl_tag("dtag5"))) test_func (int a)
{
  return a+1;
}

int test_func_attr (int __attribute__((btf_decl_tag("dtag6"))) b)
{
  return b+2;
}
