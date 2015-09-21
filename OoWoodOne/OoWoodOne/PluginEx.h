#ifndef _PLUGIN_EX_
#define _PLUGIN_EX_
#include "Plugin.h"

ulong _GNAPI(char* name, char* moduleName);//get api addr by name
void _BP(ulong addr);//set breakpoint
void _BC(ulong addr);//clear breakpoint
void _RUN();//run
void _RTR();//run to retn
ulong _POI(ulong addr);//read mem
ulong _GR(ulong reg);//get reg value,eg.REG_EAX,REG_xx
ulong _EXP(char* exp);//evaluation of expressions

#endif