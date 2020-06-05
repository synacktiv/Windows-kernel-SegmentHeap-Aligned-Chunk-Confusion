#ifndef UTILS_H
#define UTILS_H

#include <windows.h>

void hexdump(void *mem, unsigned int len);
BOOL checkPrivilege();
DWORD getProcessId(const char *processname);
void spawnShell();
DWORD GetPrivilege ( void );


#endif