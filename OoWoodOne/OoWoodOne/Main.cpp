#include <Windows.h>
#include "AsmForm.h"
#include "Plugin.h"
#include "VmpExplore.h"
#include "LogWindow.h"
#include "PluginEx.h"
///
#define RUN_STAUTS_NONE			0
#define RUN_STATUS_VMP_PATCH_HASH 1
///

#pragma comment(lib, "ollydbg.lib")

HINSTANCE hinst = NULL;
HWND hwmain = NULL;
ULONG runStatus = RUN_STAUTS_NONE;
VmpExplore* curVmpExplore=NULL;


void AnalyseVMP(void *item);
void PatchHashVMP();
void ToOEPVMP();
void FixAPIVMP();
//DLL入口点
BOOL WINAPI DllEntryPoint(HINSTANCE hi, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
		hinst = hi;
	return 1;
}
extc int _export cdecl ODBG_Plugininit(int ollydbgversion, HWND hw, ulong *features)
{
	if (ollydbgversion < PLUGIN_VERSION)
		return -1;
	if (!LogWindow::CreateLogWindow(hinst))
	{
		return -1;
	}
	hwmain = hw;
	Addtolist(0, 0, "OoWoodOne plugin v1.0");
	Addtolist(0, -1, "  Code by: OoWoodOne");
	Addtolist(0, -1, "  Date: 2015/8");
	return 0;
}
extc int _export cdecl ODBG_Plugindata(char shortname[32])
{//用于插件菜单中显示插件名
	strcpy(shortname, "OoWoodOne");
	return PLUGIN_VERSION;
}

extc int _export cdecl ODBG_Pluginmenu(int origin, char data[4096], void *item)
{
	switch (origin) 
	{
	case PM_MAIN:
		strcpy(data, "0 &VMProtect{1 &Analyse|2 &Patch Hash|3 &To OEP|0 &Fix API{4 &Address|5 &Segment}|6 &Analyse Code}|20 &ReadCommands|49 &Log Window|50 &About");
		return 1;
	case PM_DISASM:
		strcpy(data, "0 &OoWoodOne{0 &VMProtect{1 &Analyse|2 &Patch Hash ");
		strcat(data, (runStatus == RUN_STATUS_VMP_PATCH_HASH ? "finish" : "start"));
		strcat(data, "|3 &To OEP|0 &Fix API{4 &Address|5 &Segment}|6 &Analyse Code}|20 &ReadCommands}");
		return 1;
	default: 
		break;
	}
	return 0;
}


extc void _export cdecl ODBG_Pluginaction(int origin, int action, void *item)
{
	switch (origin)
	{
	case PM_MAIN:
	case PM_DISASM:
	{
		switch (action)
		{
		case 51:
		{
			//Sendshortcut(PM_MAIN, 0, WM_KEYDOWN, 0, 0, VK_F9);
			//Go(0, 0, STEP_RUN, 0, 0);
				   //HMODULE hMod = GetModuleHandle("ODbgScript.dll");
				   //if (hMod) // 检测是否被其他插件加载
				   //{
					  //  获得输出函数地址
					  // int(*pFunc)(char*) = (int(*)(char*)) GetProcAddress(hMod, "ExecuteScript");
					  // if (pFunc) // 检查是否获得输出函数
						 //  pFunc("c:/test.txt"); // 执行输出函数
				   //}
			//ulong addr = _GNAPI("MapViewOfFile", "kernel32.dll");
			//MessageBoxA(hwmain, LSFI("%08X", addr), "MapViewOfFile", MB_OK | MB_ICONINFORMATION);
				   char* filename = (char*)Plugingetvalue(VAL_EXEFILENAME);
				   MessageBoxA(hwmain, filename, "fileName",MB_OK | MB_ICONINFORMATION);
			break;
		}
		case 1:
		{
				  
			AnalyseVMP(item);
			LogWindow::ShowLogWindow();
			break;
		}
		case 2:
		{

			PatchHashVMP();
			LogWindow::ShowLogWindow();
			break;
		}
		case 3:
		{
			ToOEPVMP();
			break;
		}
		case 4:
		{
			t_dump * pd = (t_dump *)item;
			ulong addr = 0;
			if (pd)
			{
				addr = pd->sel0;
			}
			if (!addr)
			{
				addr = _GR(REG_EIP);
			}
			VmpExplore::VmpFixApiUnit(addr,Findmodule(addr),NULL);
			break;
		}
		case 5:
		{
			t_dump * pd = (t_dump *)item;
			ulong addr = 0;
			if (pd)
			{
				addr = pd->sel0;
			}
			if (!addr)
			{
				addr = _GR(REG_EIP);
			}
			VmpExplore::VmpFixApi(addr);
			LogWindow::ShowLogWindow();
			break;
		}
		case 6:
		{
			if (!curVmpExplore)
			{
				MessageBoxA(hwmain, "Please Analyse VMP First!", "Error", MB_OK);
				break;
			}
			ulong vmEip = 0;
			ulong jRV = 0;
			int vmEsp = 0;
			if ( !curVmpExplore->IsVMHandler(_GR(REG_EIP),VM_Jmp))
			{
				if (Getlong("Input ESI:", &vmEip, 4, 0, DIA_HEXONLY))
				{
					break;
				}
				jRV = vmEip - curVmpExplore->GetVMReloc();
				if (Getlong("Input VM ESP:", (ulong*)&vmEsp, 4, 0, 0))
				{
					break;
				}
			}
			else
			{
				vmEip = _POI(_GR(REG_EBP)) ;
				jRV = vmEip;
				vmEip += curVmpExplore->GetVMReloc();
				if (Getlong("Input VM ESP:", (ulong*)&vmEsp, 4, 0, 0))
				{
					break;
				}
			}
			curVmpExplore->VmpAnalyseCode(vmEip, jRV, vmEsp);
			break;
		}
		case 20:
		{
			t_dump * pd = (t_dump *)item;
			ulong addr = 0;
			if (pd)
			{
				addr = pd->sel0;
			}
			if (!addr)
			{
				addr = _GR(REG_EIP); 
			}
			Inst_UD_Chain* chain = VmpExplore::ReadCmdChain(addr,false);
			if (chain)
			{
				chain->PrintChain(true,false);
			}
			LogWindow::ShowLogWindow();
			break;
		}
		case 49:
		{
			LogWindow::ShowLogWindow();
			break;
		}
		case 50:
		{
			MessageBoxA(hwmain, "OoWoodOne plugin v1.0\r\nCode by: OoWoodOne (2015/8)", "About"
				, MB_OK | MB_ICONINFORMATION);
			break;
		}
		default:
			break;
		}
	}
	default:
		break;
	}
}

// extc void _export cdecl ODBG_Pluginmainloop(DEBUG_EVENT *debugevent)
// {
// 	if (!debugevent||!runStatus ||
// 		debugevent->u.Exception.ExceptionRecord.ExceptionCode==EXCEPTION_SINGLE_STEP)
// 	{
// 		return;
// 	}
// 
// 	switch (runStatus)
// 	{
// 	case RUN_STATUS_VMP_PATCH_HASH:
// 	{
// 		if (curVmpExplore)
// 		{
// 			if (curVmpExplore->Do_VmpPatchHash(debugevent))
// 			{
// 				runStatus = RUN_STAUTS_NONE;
// 			}
// 		}
// 		else
// 		{
// 			runStatus = RUN_STAUTS_NONE;
// 		}
// 		break;
// 	}
// 
// 
// 	default:
// 		break;
// 	}
// 
// }

extc void _export cdecl ODBG_Pluginreset(void)
{
	if (curVmpExplore)
	{
		delete curVmpExplore;
		curVmpExplore = NULL;
		runStatus = RUN_STAUTS_NONE;
	}
	LogWindow::Clear();
}

extc void _export cdecl ODBG_Plugindestroy(void)
{
	if (curVmpExplore)
	{
		delete curVmpExplore;
		curVmpExplore = NULL;
		runStatus = RUN_STAUTS_NONE;
	}
	LogWindow::DestroyLogWindow();
}

void AnalyseVMP(void *item)
{
	if (runStatus)
	{
		return;
	}
	t_dump * pd = (t_dump *)item;
	ulong addr = 0;
	if (pd)
	{
		addr = pd->sel0;
	}
	if (!addr)
	{
		addr = _GR(REG_EIP);
	}
	if (!curVmpExplore)
	{
		VmpExplore *vmp = new VmpExplore;
		if (!vmp->AnalyseVMP(addr))
		{
			delete vmp;
			vmp = NULL;
		}
		curVmpExplore = vmp;
	}
	else if (curVmpExplore->GetStartAddress() == addr)
	{
		curVmpExplore->PrintVMPInfo();
	}
	else
	{
		VmpExplore *vmp = new VmpExplore;
		if (!vmp->AnalyseVMP(addr))
		{
			delete vmp;
			vmp = NULL;
		}
		delete curVmpExplore;
		curVmpExplore = vmp;
	}
}

void PatchHashVMP()
{
	if (!runStatus)
	{
		ulong addr = _GR(REG_EIP);
		if (!curVmpExplore)
		{
			VmpExplore *vmp = new VmpExplore;
			if (!vmp->AnalyseVMP(addr))
			{
				delete vmp;
				vmp = NULL;
			}
			curVmpExplore = vmp;
		}
		else if (curVmpExplore->GetStartAddress() != addr)
		{
			VmpExplore *vmp = new VmpExplore;
			if (!vmp->AnalyseVMP(addr))
			{
				delete vmp;
				vmp = NULL;
			}
			delete curVmpExplore;
			curVmpExplore = vmp;
		}

		if (curVmpExplore)
		{
			if (curVmpExplore->VmpPatchHash())
			{
				runStatus = RUN_STATUS_VMP_PATCH_HASH;
			}
		}

	}
	else if (runStatus == RUN_STATUS_VMP_PATCH_HASH)
	{
		curVmpExplore->Do_VmpPatchHash();
	}

}

void ToOEPVMP()
{
	if (runStatus)
	{
		return;
	}
	ULONG addr_ep = Findmodule(Plugingetvalue(VAL_MAINBASE))->entry;
	if (!curVmpExplore)
	{
		VmpExplore *vmp = new VmpExplore;
		if (!vmp->AnalyseVMP(addr_ep))
		{
			delete vmp;
			vmp = NULL;
		}
		curVmpExplore = vmp;
	}
	else if (curVmpExplore->GetStartAddress() != addr_ep)
	{
		VmpExplore *vmp = new VmpExplore;
		if (!vmp->AnalyseVMP(addr_ep))
		{
			delete vmp;
			vmp = NULL;
		}
		delete curVmpExplore;
		curVmpExplore = vmp;
	}
	if (curVmpExplore)
	{
		curVmpExplore->VmpToOEPWithPathAntiDump();
	}
}
