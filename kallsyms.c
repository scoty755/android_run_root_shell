#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kallsyms.h"

bool
kallsyms_exist(void)
{
  struct stat st;

  if (stat("/proc/kallsyms", &st) < 0) {
    return false; // "/proc/kallsyms"の状態を取得
  }

  if  (st.st_mode & S_IROTH) {
    return kallsyms_get_symbol_address("_stext") != 0;
  }

  return false;
}

void *
kallsyms_get_symbol_address(const char *symbol_name)
{
  FILE *fp;
  char function[BUFSIZ];
  char symbol;
  void *address;
  int ret;

  fp = fopen("/proc/kallsyms", "r"); // "/proc/kallsyms"を開く
  if (!fp) {
    printf("Failed to open /proc/kallsyms due to %s.", strerror(errno)); // "/proc/kallsyms"の展開に失敗
    return 0;
  }

  while(!feof(fp)) {
    ret = fscanf(fp, "%p %c %s", &address, &symbol, function);
    if (ret != 3) {
      break;
    }

    if (!strcmp(function, symbol_name)) {
      fclose(fp);
      return address; // シンボルネームが一致したらアドレスを返す
    }
  }
  fclose(fp);

  return NULL;
}

