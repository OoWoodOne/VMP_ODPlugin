#include <string.h>
#include <Windows.h>
#include "PluginEx.h"

ulong _GNAPI(char* name, char* moduleName)
{
	ulong addr = 0x1000;
	int type;
	while (addr)
	{
		type = Findlabelbyname(name, &addr, addr + 1, 0x7FFFFFFF);
		if (type != NM_EXPORT)
			continue;
		t_module * module = Findmodule(addr);

		if (module)
		{
			char* mname = &module->path[strlen(module->path)];
			while (*mname != '/' && *mname != '\\' && mname >= module->path)
			{
				mname--;
			}
			mname++;
			if (_stricmp(mname, moduleName) == 0)
			{
				return addr;
			}
		}
	}
	return 0;

}


void _BP(ulong addr)
{
	Setbreakpoint(addr, TY_ACTIVE, 0);
}

void _BC(ulong addr)
{
	Setbreakpoint(addr, TY_DISABLED, 0);
}

void _RUN()
{
	//Go(0, 0, STEP_RUN, 0, 0);
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN,0,0,VK_F9);
}

void _RTR()
{
	Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 1, 0, VK_F9);
}

ulong _GR(ulong reg)
{
	t_thread* pthread = Findthread(Getcputhreadid());
	if (pthread)
	{
		switch (reg)
		{
		case REG_EAX:
		case REG_ECX:
		case REG_EDX:
		case REG_EBX:
		case REG_ESP:
		case REG_EBP:
		case REG_ESI:
		case REG_EDI:
			return pthread->reg.r[reg];
		case REG_EIP:
			return pthread->reg.ip;
		default:
			break;
		}
	}
	return 0;
}

ulong _POI(ulong addr)
{
	ulong v = 0;
	if (Readmemory(&v, addr, 4, MM_RESILENT) != 4)
	{
		v = 0;
	}
	return v;
}

ulong _EXP(char* exp)
{
	return 0;
}