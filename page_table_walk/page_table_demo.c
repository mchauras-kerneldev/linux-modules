#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARR_SIZE 128 * 1024 * 1024

int main() {
  int a = 0;
  char *s = "Mukesh Kumar Chaursiya";
  char *temp = (char *)malloc(ARR_SIZE);
  printf("Integer Value address %p\n", &a);
  printf("Char Pointer address %p with len %ld\n", s, strlen(s));
  printf("Address of large char pointer start: %p\tend: %p\n", temp,
         temp + (ARR_SIZE)-1);
  memset(temp, 0, ARR_SIZE);
  while (1) {
    temp[a] = a;
    if (a >= ARR_SIZE) {
      a = 0;
    }
		a++;
    sleep(1000);
  }
}
