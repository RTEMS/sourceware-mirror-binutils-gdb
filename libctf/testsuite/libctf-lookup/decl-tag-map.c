#include "config.h"
#include <ctf-api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main (int argc, char *argv[])
{
  ctf_archive_t *ctf;
  ctf_dict_t *fp;
  int err;
  ctf_id_t decl_id = 0;
  ctf_id_t decl_tag_id = 0;
  int64_t comp_idx;
  ctf_next_t *it = NULL;
  ctf_next_t *it2 = NULL;
  const char *name = NULL;
  char *foo1, *foo2;

  if (argc != 2)
    {
      fprintf (stderr, "Syntax: %s PROGRAM\n", argv[0]);
      exit (1);
    }

  if ((ctf = ctf_open (argv[1], NULL, &err)) == NULL)
    goto open_err;
  if ((fp = ctf_dict_open (ctf, NULL, &err)) == NULL)
    goto open_err;

  while ((decl_id = ctf_variable_next (fp, &it, &name)) != CTF_ERR)
    {
      it2 = NULL;
      while ((decl_tag_id = ctf_decl_tag_next (fp, decl_id, &comp_idx, &it2))
	     != CTF_ERR)
	printf ("%s has tag %s with idx %ld\n", foo1 = ctf_type_aname (fp, decl_id),
		foo2 = ctf_type_aname (fp, decl_tag_id), comp_idx);
    }

  it = NULL;
  while ((decl_id = ctf_type_kind_next (fp, &it, CTF_K_FUNC_LINKAGE))
	 != CTF_ERR)
    {
      while ((decl_tag_id = ctf_decl_tag_next (fp, decl_id, &comp_idx, &it2))
	     != CTF_ERR)
	printf ("%s has tag %s with idx %ld\n", foo1 = ctf_type_aname (fp, decl_id),
		foo2 = ctf_type_aname (fp, decl_tag_id), comp_idx);
    }

  ctf_dict_close (fp);
  ctf_close (ctf);
  return 0;

open_err:
  fprintf (stderr, "%s: cannot open: %s\n", argv[0], ctf_errmsg (err));
  return 1;
lookup_err:
  fprintf (stderr, "Lookup failed: %s\n", ctf_errmsg (ctf_errno (fp)));
  fprintf (stderr, "Failing ctf_id: %s\n", ctf_type_aname (fp, decl_id));
  return 1;
}
