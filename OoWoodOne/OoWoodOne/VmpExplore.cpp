#include <Windows.h>
#include "AsmForm.h"
#include "Plugin.h"
#include "LogWindow.h"
#include "VmpExplore.h"
#include "resource.h"
#include "PluginEx.h"
#include "PEDiy.h"

VmpExplore::VmpExplore()
{
	_contextCount = 0;
	_progress = 0;
	_entryChain = new Inst_UD_Chain; 
	_patchHashDataAddr = 0;
	memset(&_context, 0, sizeof(vmp_cxt_unit)*MAX_VM_CONTEXT_COUNT);
	memset(&_retContext, 0, sizeof(vmp_cxt_unit)*MAX_VM_RET_CONTEXT_COUNT);
	memset(&_vmEntry, 0, sizeof(simple_cmd_group));
	memset(&_dispatchInfo, 0, sizeof(vmp_dispatch_info));
	memset(&_handlerDecode, 0, sizeof(simple_cmd_group));
	memset(&_initkeyInfo, 0, sizeof(vmp_initkey_info));
	memset(_handlers, 0, sizeof(vmp_handler)*VMP_HANDLER_DECODE_CONST);
	memset(&_checkEsp, 0, sizeof(simple_cmd_info));
	memset(&_handlersAddr, 0, sizeof(_handlersAddr));
	memset(&_patchHashData, 0, sizeof(vmp_patch_hash));
	_dispatchInfo.opcodeJoinReg = REG_INDEX_NONE;
}

VmpExplore::~VmpExplore()
{
	Clear();
	if (_entryChain)
		delete _entryChain;
}

void earseCmdGroup(simple_cmd_group* g)
{
	if (!g || !g->header)
		return;
	simple_cmd_info* tmp = g->header;
	while (tmp)
	{
		simple_cmd_info* tmp0 = tmp->nextCmd;
		delete tmp;
		tmp = tmp0;
	}
	memset(g, 0, sizeof(simple_cmd_group));

}

void addCmdToGroup(simple_cmd_group* g, simple_cmd_info* c)
{
	if (!g->tail)
	{
		g->header = g->tail = c;
		return;
	}
	g->tail->nextCmd = c;
	c->preCmd = g->tail;
	g->tail = c;
}

void addCmdToGroupHeader(simple_cmd_group* g, simple_cmd_info* c)
{
	if (!g->tail)
	{
		g->header = g->tail = c;
		return;
	}
	g->header->preCmd = c;
	c->nextCmd = g->header;
	g->header = c;
}

simple_cmd_info* createCmdFromUDNode(Inst_UD_Node* node,const char* note)
{
	simple_cmd_info * cmdinfo = new simple_cmd_info;
	memset(cmdinfo, 0, sizeof(simple_cmd_info));
	cmdinfo->cmdInfo = node->cmdInfo;
	if (note)
	{
		strcpy(cmdinfo->note, note);
	}
	return cmdinfo;
}

void VmpExplore::Clear()
{
	_contextCount = 0;
	_progress = 0;
	_patchHashDataAddr = 0;
	earseCmdGroup(&_handlerDecode);
	earseCmdGroup(&_vmEntry);
	earseCmdGroup(&_dispatchInfo.opcodeDecode);
	earseCmdGroup(&_initkeyInfo.initkeyDecode);
	for (ulong i = 0; i < VMP_HANDLER_DECODE_CONST; i++)
	{
		if (_handlers[i].handlerChain && !_handlers[i].isCopy)
		{
			delete _handlers[i].handlerChain;
		}
			
		earseCmdGroup(&_handlers[i].handlerCmds);
	}
	memset(&_vmEntry, 0, sizeof(simple_cmd_group));
	memset(_handlers, 0, sizeof(vmp_handler)*VMP_HANDLER_DECODE_CONST);
	memset(&_context, 0, sizeof(vmp_cxt_unit)*MAX_VM_CONTEXT_COUNT);
	memset(&_retContext, 0, sizeof(vmp_cxt_unit)*MAX_VM_RET_CONTEXT_COUNT);
	memset(&_dispatchInfo, 0, sizeof(vmp_dispatch_info));
	memset(&_initkeyInfo, 0, sizeof(vmp_initkey_info));
	memset(_handlers, 0, sizeof(vmp_handler)*VMP_HANDLER_DECODE_CONST);
	memset(&_checkEsp, 0, sizeof(simple_cmd_info));
	if (_entryChain)
		_entryChain->ClearChain();
	for (ulong i = 0; i < VMH_End; i++)
	{
		vmp_handler_addr* tmp = _handlersAddr[i];
		vmp_handler_addr* tmp0;
		while (tmp)
		{
			if (tmp)
				earseCmdGroup(&tmp->dataDecode);
			tmp0 = tmp;
			tmp = tmp->next;
			delete tmp0;
		}
	}


	memset(&_handlersAddr, 0, sizeof(_handlersAddr));
	memset(&_patchHashData, 0, sizeof(vmp_patch_hash));
	_dispatchInfo.opcodeJoinReg = REG_INDEX_NONE;
}

bool VmpExplore::AnalyseVMP(ulong addr)
{
	Clear();
	if (AnalyseEntry(addr))
	{
		if (AnalyseHandlers())
		{
			PrintHandlers();
			PrintHandlersAddr();
			if (AnalyseRetContext())
			{
				PrintRetContext();
			}
			AnalyseEntryCode();
			Progress(1000, "VMProtect Analyse Finished!");
			//LOG(0, NULL);
			//LOG(0, "VMProtect Analyse Successfully!", NULL);
			//LOG(0,NULL);
			Mergequicknames();
			return true;
		}
	}
	LOG(0, "VMProtect Analyse Failed!", NULL, LOG_HILITE);
	Progress(0, "VMProtect Analyse Failed!");
	Mergequicknames();
	return false;
}

Inst_UD_Chain* VmpExplore::ReadCmdChain(ulong addr, bool optimize, int maxCmdCount, bool showLog)
{
	char cmd[MAXCMDSIZE];
	t_thread* pthread = Findthread(Getcputhreadid());
	if (!pthread)
		return NULL;
	Inst_UD_Chain* ret = new Inst_UD_Chain;
	ulong ip;
	if (!addr)
	{
		ip= pthread->reg.ip;
	}
	else
	{
		ip = addr;
	}
	bool exit = false;
	int cmdnum = 0;
	t_disasm *pDisasm = new t_disasm;
	while (1)
	{
		memset(pDisasm, 0, sizeof(t_disasm));
		ulong cmdlen = Readcommand(ip, cmd);
		cmdlen = Disasm((uchar*)cmd, cmdlen, ip, NULL, pDisasm, DISASM_FILE, NULL);
		if (cmdlen == 0)
		{
			delete pDisasm;
			if (showLog)
				LOG(ip, "VMP read command failed!", NULL, LOG_HILITE);
			delete ret;
			return NULL;
		}
		if (pDisasm->cmdtype == C_JMP || pDisasm->cmdtype == C_CAL)
		{
			ip = pDisasm->jmpaddr;
			if (!ip)
			{
				exit = true;
			}
		}
		else if (pDisasm->cmdtype == C_RET)
		{
			exit = true;
		}
		else
		{
			ip += cmdlen;
		}
		if (!ret->AddNode(pDisasm, cmd, cmdlen, optimize))
		{
			delete pDisasm;
			if (showLog)
				LOG(ip, "VMP add to chain failed!", NULL, LOG_HILITE);
			delete ret;
			return NULL;
		}
		else if (pDisasm->cmdtype == C_JMC && !ret->FindNode(pDisasm->jmpaddr))//循环则跳过
		{
			//获取跳转前一个指令（判断标志位）
			Inst_UD_Node* node = ret->GetTail()->preNode;
			if (node)
			{
				int isjmp;
				if (JccJump(ret->GetTail()->cmdInfo.optType, node, &isjmp))
				{
					if (isjmp == 1)
					{
						ip = pDisasm->jmpaddr;
					}
				}
				else
				{

					ip = pDisasm->jmpaddr;
				}
			}

		}
		cmdnum++;
		if (cmdnum > maxCmdCount)
		{
			delete pDisasm;
			if (showLog)
				LOG(ip, "VMP read command outside commnd count!", NULL, LOG_HILITE);
			delete ret;
			return NULL;
		}
		if (exit)
			break;

	}
	delete pDisasm;
	if (optimize)
		ret->OptimizeChain();
	
	return ret;

}

bool VmpExplore::GetVMhandlerEntry(ulong addr)
{
	char cmd[MAXCMDSIZE];
	t_thread* pthread = Findthread(Getcputhreadid());
	if (!pthread)
		return NULL;
	Inst_UD_Chain* ret = new Inst_UD_Chain;
	ulong ip;
	if (!addr)
	{
		ip = pthread->reg.ip;
	}
	else
	{
		ip = addr;
	}
	bool exit = false;
	int cmdnum = 0;
	t_disasm *pDisasm = new t_disasm;
	while (1)
	{
		memset(pDisasm, 0, sizeof(t_disasm));
		ulong cmdlen = Readcommand(ip, cmd);
		cmdlen = Disasm((uchar*)cmd, cmdlen, ip, NULL, pDisasm, DISASM_FILE, NULL);
		if (cmdlen == 0)
		{
			delete pDisasm;
			LOG(ip, "VMP read command failed!", NULL, LOG_HILITE);
			delete ret;
			return false;
		}
		if (pDisasm->cmdtype == C_JMP || pDisasm->cmdtype == C_CAL)
		{
			ip = pDisasm->jmpaddr;
		}
		else if (pDisasm->cmdtype == C_RET)
		{
			exit = true;
		}
		else
		{
			ip += cmdlen;
		}
		bool status0 = ret->AddNode(pDisasm, cmd, cmdlen, false);
		if (!status0)
		{
			delete pDisasm;
			LOG(ip, "VMP add to chain failed!", NULL, LOG_HILITE);
			delete ret;
			return false;
		}
		else if (pDisasm->cmdtype != C_JMP && pDisasm->cmdtype != C_CAL &&
			pDisasm->jmpaddr != 0 && !ret->FindNode(pDisasm->jmpaddr))//循环则跳过
		{
			Inst_UD_Node* node = ret->GetTail()->preNode;
			if (node)
			{
				int isjmp;
				if (JccJump(ret->GetTail()->cmdInfo.optType, node, &isjmp))
				{
					if (isjmp == 1)
					{
						ip = pDisasm->jmpaddr;
					}
				}
				else if (!GetVMhandlerEntry(pDisasm->jmpaddr))
				{
					delete pDisasm;
					delete ret;
					return false;
				}
			}
			else if (!GetVMhandlerEntry(pDisasm->jmpaddr))
			{
				delete pDisasm;
				delete ret;
				return false;
			}

		}
		else
		{
			//可能为无效指令（到了空的内存区域）

			if (ret->GetTail()->cmdInfo.optType == ASM_ADD)
			{
				int i = 0;
				for (i = 0; i < MAXCMDSIZE; i++)
				{
					if (cmd[i])
					{
						break;
					}
				}
				if (i == MAXCMDSIZE)
				{
					delete pDisasm;
					delete ret;
					return true;
				}
			}
		}
		cmdnum++;
		if (cmdnum > MAX_VMP_ENTRY_CMD_COUNT)
		{
			delete pDisasm;
			LOG(ip, "VMP read command outside commnd count!", NULL, LOG_HILITE);
			delete ret;
			return false;
		}
		if (exit)
			break;

	}
	delete pDisasm;

	simple_cmd_info* tmp1 = _vmEntry.header;
	while (tmp1)
	{
		if (tmp1->cmdInfo.ip == ret->GetTail()->cmdInfo.ip)
		{
			break;
		}
		tmp1 = tmp1->nextCmd;
	}
	if (!tmp1)
	{
		simple_cmd_info* cmdinfo = new simple_cmd_info;
		cmdinfo->cmdInfo = ret->GetTail()->cmdInfo;
		strcpy(cmdinfo->note, "VM Entry");
		cmdinfo->nextCmd = 0;
		cmdinfo->preCmd = 0;
		addCmdToGroup(&_vmEntry, cmdinfo);
	}
	delete ret;
	return true;

}

Inst_UD_Chain* VmpExplore::ReadHandlerCmdChain(ulong addr, bool mode, int maxCmdCount)
{
	char cmd[MAXCMDSIZE];
	t_thread* pthread = Findthread(Getcputhreadid());
	if (!pthread)
		return NULL;
	Inst_UD_Chain* ret = new Inst_UD_Chain;
	ulong ip;
	if (!addr)
	{
		ip = pthread->reg.ip;
	}
	else
	{
		ip = addr;
	}
	bool exit = false;
	int cmdnum = 0;
	t_disasm *pDisasm = new t_disasm;
	while (1)
	{
		memset(pDisasm, 0, sizeof(t_disasm));
		ulong cmdlen = Readcommand(ip, cmd);
		cmdlen = Disasm((uchar*)cmd, cmdlen, ip, NULL, pDisasm, DISASM_FILE, NULL);
		if (cmdlen == 0)
		{
			delete pDisasm;
			LOG(ip, "VMP read command failed!", NULL, LOG_HILITE);
			delete ret;
			return NULL;
		}
		if (pDisasm->cmdtype == C_JMP || pDisasm->cmdtype == C_CAL)
		{
			ip = pDisasm->jmpaddr;
		}
		else if (pDisasm->cmdtype == C_RET)
		{
			exit = true;
		}
		else
		{
			ip += cmdlen;
		}
		bool status0;
		if (mode)
		{
			status0 = ret->AddNode(pDisasm, cmd, cmdlen);
		}
		else
		{
#if _DEBUG
			status0 = ret->AddNode(pDisasm, cmd, cmdlen);
#else
			status0 = ret->AddNode(pDisasm, cmd, cmdlen,false);
#endif
		}

		if (!status0)
		{
			delete pDisasm;
			LOG(ip, "VMP add to chain failed!", NULL, LOG_HILITE);
			delete ret;
			return NULL;
		}
		else if (pDisasm->cmdtype != C_JMP && pDisasm->cmdtype != C_CAL && 
			pDisasm->jmpaddr != 0 && !ret->FindNode(pDisasm->jmpaddr))//循环则跳过
		{
			//获取跳转前一个指令（判断标志位）
			Inst_UD_Node* node = ret->GetTail()->preNode;
			if (node)
			{
				int isjmp;
				if (JccJump(ret->GetTail()->cmdInfo.optType, node, &isjmp))
				{
					if (isjmp == 1)
					{
						ip = pDisasm->jmpaddr;
					}
				}
				else if (!_checkEsp.cmdInfo.ip)
				{
					Inst_UD_Node* tmp = node;
					ulong maxcheck = 5;//在5个有效指令内检测
					while (tmp && maxcheck)
					{
						if (!tmp->isDiscarded)
						{
							ulong opt = tmp->cmdInfo.op[0].opType&tmp->cmdInfo.op[1].opType;
							if (!(tmp->cmdInfo.optType == ASM_CMP 
								&& opt&OP_REG
								&& opt&OP_DWORD))
							{
								//LOG(node->cmdInfo.ip, node->cmdInfo.cmd);
								//LOG(pDisasm->ip, pDisasm->result);
							}
							else
							{
								_checkEsp.cmdInfo = tmp->cmdInfo;
								strcpy(_checkEsp.note, "VMP Check ESP");
								ip = pDisasm->jmpaddr;



							}
							maxcheck--;
						}
						tmp = tmp->preNode;
						
					}
				}
			}
			else
			{
				//LOG(pDisasm->ip, pDisasm->result);
			}

		}
		else
		{
			//可能为无效指令（到了空的内存区域）

			if (ret->GetTail()->cmdInfo.optType == ASM_ADD)
			{
				int i = 0;
				for (i = 0; i < MAXCMDSIZE; i++)
				{
					if (cmd[i])
					{
						break;
					}
				}
				if (i == MAXCMDSIZE)
				{
					delete pDisasm;
					delete ret;
					return NULL;
				}
			}
		}
		cmdnum++;
		if (cmdnum > maxCmdCount)
		{
			delete pDisasm;
			LOG(ip, "VMP read command outside commnd count!", NULL, LOG_HILITE);
			delete ret;
			return NULL;
		}
		if (exit || ip == _checkEsp.cmdInfo.ip || ip == _dispatchInfo.opcodeLoadIP)
			break;

	}
	delete pDisasm;
	if (mode)
	{
		ret->OptimizeChain();
	}
	else
	{
#if _DEBUG
		ret->OptimizeChain();
#endif
	}



	return ret;

}


bool VmpExplore::JccJump(ulong jcc, Inst_UD_Node* eflCmd, int* isJmp)
{
	char efl[8];
	memset(efl, 0xFF, 8);
	switch (eflCmd->cmdInfo.optType)
	{
	case ASM_SUB:
	{
		if ((eflCmd->cmdInfo.op[0].reg&ud_esp || eflCmd->cmdInfo.op[0].reg&ud_ebp ) && (int)(eflCmd->cmdInfo.op[1].opConst) < 0)
		{
			efl[efl_CF] = 1;
			efl[efl_AF] = 1;
			efl[efl_ZF] = 0;
			efl[efl_SF] = 0;
			efl[efl_OF] = 0;
		}
		break;
	}
	case ASM_ADD:
	{
		if ((eflCmd->cmdInfo.op[0].reg&ud_esp || eflCmd->cmdInfo.op[0].reg&ud_ebp ) && (int)(eflCmd->cmdInfo.op[1].opConst) > 0)
		{
			efl[efl_CF] = 0;
			efl[efl_AF] = 0;
			efl[efl_ZF] = 0;
			efl[efl_SF] = 0;
			efl[efl_OF] = 0;
		}
		break;
	}
	case ASM_STC:
	{
		efl[efl_CF] = 1;
		break;
	}
	case ASM_CLC:
	{
		efl[efl_CF] = 0;
		break;
	}
	default:
		break;
	}

	switch (jcc)
	{
	case ASM_JC:
	case ASM_JB:
	case ASM_JNAE:
	{
		if (efl[efl_CF]==0xFF)
		{
			break;
		}
		if (efl[efl_CF] == 1)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JNC:
	case ASM_JAE:
	case ASM_JNB:
	{
		if (efl[efl_CF]==0xFF)
		{
			break;
		}
		if (efl[efl_CF] ==0)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JZ:
	case ASM_JE:
	{
		if (efl[efl_ZF]==0xFF)
		{
			break;
		}
		if (efl[efl_ZF] == 1)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JNZ:
	case ASM_JNE:
	{
		if (efl[efl_ZF]==0xFF)
		{
			break;
		}
		if (efl[efl_ZF] == 0)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JP:
	case ASM_JPE:
	{
		if (efl[efl_PF]==0xFF)
		{
			break;
		}
		if (efl[efl_PF] == 1)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JNP:
	case ASM_JPO:
	{
		if (efl[efl_PF]==0xFF)
		{
			break;
		}
		if (efl[efl_PF] == 0)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JS:
	{
		if (efl[efl_SF]==0xFF)
		{
			break;
		}
		if (efl[efl_SF] == 1)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JNS:
	{
		if (efl[efl_SF]==0xFF)
		{
			break;
		}
		if (efl[efl_SF] == 0)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JO:
	{
		if (efl[efl_OF] == 0xFF)
		{
			break;
		}
		if (efl[efl_OF] == 1)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JNO:
	{
		if (efl[efl_OF]==0xFF)
		{
			break;
		}
		if (efl[efl_OF] == 0)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JA:
	case ASM_JNBE:
	{
		if ((efl[efl_CF] | efl[efl_ZF])==0xFF)
		{
			break;
		}
		if (efl[efl_CF] == 0 && efl[efl_ZF] == 0)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JBE:
	case ASM_JNA:
	{
		if ((efl[efl_CF] | efl[efl_ZF]) == 0xFF)
		{
			break;
		}
		if (efl[efl_CF] == 1 || efl[efl_ZF] == 1)
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JG:
	case ASM_JNLE:
	{
		if ((efl[efl_SF] | efl[efl_ZF] | efl[efl_OF]) == 0xFF)
		{
			break;
		}
		if (efl[efl_ZF] == 0  && efl[efl_SF] == efl[efl_OF])
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JLE:
	case ASM_JNG:
	{
		if ((efl[efl_SF] | efl[efl_ZF] | efl[efl_OF]) == 0xFF)
		{
			break;
		}
		if (efl[efl_ZF] == 1 && efl[efl_SF] != efl[efl_OF])
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JL:
	case ASM_JNGE:
	{
		if ((efl[efl_SF] | efl[efl_OF]) == 0xFF)
		{
			break;
		}
		if (efl[efl_SF] != efl[efl_OF])
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	case ASM_JGE:
	case ASM_JNL:
	{
		if ((efl[efl_SF] | efl[efl_OF]) == 0xFF)
		{
			break;
		}
		if (efl[efl_SF] == efl[efl_OF])
		{
			*isJmp = 1;
		}
		else
		{
			*isJmp = 0;
		}
		return true;
	}
	default:
		break;
	}
	*isJmp = -1;
	return false;
}

bool VmpExplore::AnalyseEntry(ulong addr)
{
	_progress = 100;
	Progress(_progress, "Read Command info...");
	Clear();
	_entryChain = ReadCmdChain(addr);
	if (!_entryChain)
	{
		return false;
	}
	_progress += 100;
	Progress(_progress, "Analyse Dispatch Info...");
	if (!AnalyseDispatchInfo(_entryChain))
	{
		return false;
	}
	_progress += 100;
	Progress(_progress, "Analyse Initkey Info...");
	if (!AnalyseInitkeyInfo())
	{
		return false;
	}
	_progress += 50;
	Progress(_progress, "Analyse Handler Decode Info...");
	if (!AnalyseHandlerDecode())
	{
		return false;
	}
	_progress += 50;
	Progress(_progress, "ReAnalyse dispatch Info...");
	if (!ReAnalyseDispatchInfo())
	{
		return false;
	}
	PrintInitkeyInfo();
	PrintContext();
	PrintDispatchInfo();
	PrintHandlerDecode();
	PrintCheckEsp();
	PrintVMEntry();

	return true;
}

bool VmpExplore::AnalyseInitkeyInfo()
{

	_initkeyInfo.relocJoinReg = REG_INDEX_NONE;
	Inst_UD_Node* tmp = _entryChain->GetTail();
	while (tmp)
	{
		//寻找最后引用initkey（esp-4）的指令
		if (tmp->isDiscarded)
		{
			tmp = tmp->preNode;
			continue;
		}
		if (tmp->espPosRef == -4)
		{
			break;
		}
		tmp = tmp->preNode;
	}
	if (!tmp)
	{
		LOG(0,"VMP entry analyse decode info failed1!",NULL,LOG_HILITE);
		return false;
	}
	ulong reg = tmp->cmdInfo.op[0].reg;
	if (!reg)
	{
		LOG(0, "VMP entry analyse decode info failed2!", NULL, LOG_HILITE);
		return false;
	}
	_initkeyInfo.initkeyDecodeReg = RegType2RegIndex(reg);
	addCmdToGroup(&_initkeyInfo.initkeyDecode, createCmdFromUDNode(tmp,"Initkey Load"));

	//寻找所有initkey解密命令
	ulong udReg = reg;
	tmp = tmp->nextNode;
	while (tmp)
	{
		if (tmp->isDiscarded)
		{
			tmp = tmp->nextNode;
			continue;
		}
		if (_initkeyInfo.relocJoinReg == -1 && tmp->espPosRRef <= MIN_VM_CONTEXT_COUNT*-4 && tmp->espPosRRef >= MAX_VM_CONTEXT_COUNT*-4)
		{
			reg = tmp->cmdInfo.op[0].reg;
			if (reg && !(reg&REG_ESP))
			{
				//根据RELOC引用来确定context大小
				_contextCount = tmp->espPosRRef / -4;
				_initkeyInfo.relocJoinReg = RegType2RegIndex(reg);
				addCmdToGroup(&_initkeyInfo.initkeyDecode, createCmdFromUDNode(tmp,"Reloc Load"));
			}
		}
		else if (tmp->opDef&udReg)
		{
			reg = tmp->cmdInfo.op[1].reg;
			if (reg)
			{
				if (RegType2RegIndex(reg) != _initkeyInfo.relocJoinReg)
				{
					LOG(0, "VMP entry analyse decode info failed3!", NULL, LOG_HILITE);
					return false;
				}
				else
				{
					addCmdToGroup(&_initkeyInfo.initkeyDecode, createCmdFromUDNode(tmp, "Reloc Add"));
				}
			}
			else
			{
				addCmdToGroup(&_initkeyInfo.initkeyDecode, createCmdFromUDNode(tmp,"InitKey Decode"));
			}

		}
		else if (tmp->opRef&udReg && tmp->cmdInfo.op[1].opType&OP_MEM)//opcode load
		{
			break;
		}
		tmp = tmp->nextNode;
	}
	if (!tmp)
	{
		LOG(0, "VMP entry analyse decode info failed4!", NULL, LOG_HILITE);
		return false;
	}
	


	//分析Context
	if (!AnalyseContext())
	{
		return false;
	}
	_initkeyInfo.initkeyValue = _context[_contextCount - 1].value;
	return true;
}

bool VmpExplore::AnalyseDispatchInfo(Inst_UD_Chain* chain, bool foundJoinReg)
{
	Inst_UD_Node* tmp = chain->GetHeader();
	t_module* module = Findmodule(tmp->cmdInfo.ip);
	if (!module)
	{
		return false;
	}

	while (tmp->nextNode)
	{
		if (tmp->isDiscarded)
		{
			tmp = tmp->nextNode;
			continue;
		}
		if (tmp->cmdInfo.optType == ASM_MOV && tmp->cmdInfo.op[1].opConst >= module->base && tmp->cmdInfo.op[1].opConst <= module->base + module->size)
		{
			ulong reg0 = tmp->cmdInfo.op[0].reg;
			ulong reg1 = tmp->cmdInfo.op[1].reg;
			if (!reg0 || !reg1)
			{
				tmp = tmp->nextNode;
				continue;
			}
			
			_dispatchInfo.idspReg = RegType2RegIndex(reg0);
			_dispatchInfo.indexReg = RegType2RegIndex(reg1);
			_dispatchInfo.opcodeDecodeReg = _dispatchInfo.indexReg;
			_dispatchInfo.tableBase = tmp->cmdInfo.op[1].opConst;
			_dispatchInfo.dispatchCmd.cmdInfo = tmp->cmdInfo;
			strcpy(_dispatchInfo.dispatchCmd.note, "VMP Dispatch Address");
			break;
		}
		tmp = tmp->nextNode;
	}
	if (!tmp)
	{
		LOG(0, "VMP entry dispatch info not found!", NULL, LOG_HILITE);
		return false;
	}
	//_dispatchInfo.opcodeJoinReg = REG_INDEX_NONE;
	ulong udReg = RegIndex2RegType(_dispatchInfo.indexReg);
	tmp = tmp->preNode;
	while (tmp)
	{
		if (tmp->isDiscarded)
		{
			tmp = tmp->preNode;
			continue;
		}
		if (tmp->opDef&udReg)
		{
			if (!(tmp->cmdInfo.op[1].opType & OP_MEM))
			{
				int reg = tmp->cmdInfo.op[1].reg;
				int regIndex = RegType2RegIndex(reg);
				if (_dispatchInfo.opcodeJoinReg == REG_INDEX_NONE && reg && regIndex != _dispatchInfo.indexReg)
				{
					_dispatchInfo.opcodeJoinReg = regIndex;
				}
				addCmdToGroupHeader(&_dispatchInfo.opcodeDecode, createCmdFromUDNode(tmp, "Opcode Decode"));
			}
			else
			{
				addCmdToGroupHeader(&_dispatchInfo.opcodeDecode, createCmdFromUDNode(tmp, "VMP Opcode Load"));
				_dispatchInfo.esiOffset = tmp->cmdInfo.op[1].opConst;
				_dispatchInfo.opcodeLoadIP = tmp->cmdInfo.ip;
				break;
			}
		}
		else if(tmp->opRef&udReg)
		{
			if (_dispatchInfo.opcodeJoinReg != REG_INDEX_NONE)
			{
				ulong udReg0 = RegIndex2RegType(_dispatchInfo.opcodeJoinReg);
				if (tmp->opDef&udReg0)
				{
					addCmdToGroupHeader(&_dispatchInfo.opcodeDecode, createCmdFromUDNode(tmp, "Join Reg Do"));
				}
			}
		}
		
		tmp = tmp->preNode;
	}
	if (!tmp)
	{
		LOG(0, "VMP entry opcode load not found!", NULL, LOG_HILITE);
		return false;
	}

	if (foundJoinReg && _dispatchInfo.opcodeJoinReg != REG_INDEX_NONE)
	{
		udReg = RegIndex2RegType(_dispatchInfo.opcodeJoinReg);
		tmp = tmp->preNode;

		while (tmp)
		{
			if (tmp->isDiscarded)
			{
				tmp = tmp->preNode;
				continue;
			}
			if (tmp->opDef&udReg)
			{
				addCmdToGroupHeader(&_dispatchInfo.opcodeDecode, createCmdFromUDNode(tmp, "Join Reg Load"));
				break;
			}

			tmp = tmp->preNode;
		}
	}

	Inst_UD_Node* tmp0 = chain->GetTail();
	while (tmp0)
	{

		if (tmp0->cmdInfo.ip == _dispatchInfo.opcodeLoadIP)
		{
			break;
		}
		if (tmp0->cmdInfo.op[0].reg == ud_esi)
		{
			switch (tmp0->cmdInfo.optType)
			{
			case ASM_INC:
				_dispatchInfo.esiChange += 1;
				break;
			case ASM_DEC:
				_dispatchInfo.esiChange += (-1);
				break;
			case ASM_LEA:
				if (tmp0->cmdInfo.op[1].reg == ud_esi)
				{
					_dispatchInfo.esiChange += tmp0->cmdInfo.op[1].opConst;
				}
				break;
			case ASM_ADD:
				if (tmp0->cmdInfo.op[1].opType&OP_IMM)
				{
					_dispatchInfo.esiChange += tmp0->cmdInfo.op[1].opConst;
				}
				break;
			case ASM_SUB:
				if (tmp0->cmdInfo.op[1].opType&OP_IMM)
				{
					_dispatchInfo.esiChange += (-(int)tmp0->cmdInfo.op[1].opConst);
				}
				break;
			default:
				break;
			}
		}
		tmp0 = tmp0->preNode;
	}

	if (!tmp)
	{
		LOG(0, "VMP entry join reg load not found!", NULL, LOG_HILITE);
		return false;
	}

	if (!GetVMhandlerEntry(_dispatchInfo.dispatchCmd.cmdInfo.ip))
	{
		LOG(0, "VMP entry get vmhandler entry error!", NULL, LOG_HILITE);
		return false;
	}
	return true;

}

bool VmpExplore::AnalyseHandlerDecode()
{
	if (!_dispatchInfo.dispatchCmd.cmdInfo.ip)
	{
		return false;
	}
	Inst_UD_Node* tmp = _entryChain->GetTail();
	ulong ud_reg = RegIndex2RegType(_dispatchInfo.idspReg);
	bool inCode = false;
	while (tmp && tmp->cmdInfo.ip != _dispatchInfo.dispatchCmd.cmdInfo.ip)
	{
		if (tmp->isDiscarded)
		{
			tmp = tmp->preNode;
			continue;
		}
		//查找入栈前
		if (!inCode && tmp->opRef & ud_reg && tmp->espPosDef)
		{
			inCode = true;
		}
		if (inCode && tmp->opDef & ud_reg)
		{
			addCmdToGroup(&_handlerDecode, createCmdFromUDNode(tmp,"Handler Decode"));
		}
		tmp = tmp->preNode;
	}
	return true;
}

ulong GetRegValue(t_thread* pthread,int index)
{
	switch (index)
	{
		case REG_EAX:
		{
			return pthread->context.Eax;
		}
		case REG_ECX:
		{
			return pthread->context.Ecx;
		}
		case REG_EDX:
		{
			return pthread->context.Edx;
		}
		case REG_EBX:
		{
			return pthread->context.Ebx;
		}
		case REG_ESP:
		{
			return pthread->context.Esp;
		}
		case REG_EBP:
		{
			return pthread->context.Ebp;
		}
		case REG_ESI:
		{
			return pthread->context.Esi;
		}
		case REG_EDI:
		{
			return pthread->context.Edi;
		}
		default:
		{
			return 0;
		}
	}
}

bool GetContextByEspDef(Inst_UD_Node*cn, vmp_cxt_unit* cu)
{
	t_thread* pthread = Findthread(Getcputhreadid());
	//call 类型
	if (cn->cmdInfo.optType == ASM_CALL)
	{
		cu->value = cn->cmdInfo.ip + cn->cmdInfo.cmdLen;
	}
	//pushaf 类型
	else if (cn->cmdInfo.optType == ASM_PUSHFD)
	{
		strcpy(cu->remark, "EFL");
		cu->value = pthread->context.EFlags;
	}
	//push 类型
	else if (cn->cmdInfo.optType == ASM_PUSH)
	{
		if (cn->cmdInfo.op[0].opType&OP_MEM)
		{
			ulong v = 0;
			if (Readmemory(&v, cn->cmdInfo.op[0].opConst, 4, MM_RESILENT) != 4)
			{
				return false;
			}
			cu->value = v;
			//memory only ANTIDUMP
			strcpy(cu->remark, "ANTIDUMP");

		}
		else
		{
			if (cn->cmdInfo.op[0].opType&OP_IMM)
			{
				cu->value = cn->cmdInfo.op[0].opConst;
			}
			else
			{
				ulong regindex = RegType2RegIndex(cn->cmdInfo.op[0].reg);
				strcpy(cu->remark, GET_REG_KEY(regindex));
				cu->value = GetRegValue(pthread, regindex);
			}
		}
	}
	//mov、xchg类型，直接获取第二个参数
	else if (!cn->espPosRef)
	{
		if (!cn->cmdInfo.op[1].opType || cn->cmdInfo.op[1].opType&OP_MEM)
		{
			return false;
		}
		if (cn->cmdInfo.op[1].opType&OP_IMM)
		{
			cu->value = cn->cmdInfo.op[1].opConst;
		}
		else
		{
			ulong regindex = RegType2RegIndex(cn->cmdInfo.op[1].reg);
			strcpy(cu->remark, GET_REG_KEY(regindex));
			cu->value = GetRegValue(pthread, regindex);
		}

	}
	//pop [esp+xx]类型的，寻找上一个定义用
	else
	{
		Inst_UD_Node* tmp0 = cn->preNode;
		while (tmp0)
		{
			if (tmp0->espPosDef = cn->espPosRef)
			{
				break;
			}
			tmp0 = tmp0->preNode;
		}
		if (!tmp0)
		{
			return false;
		}

		//efl 类型
		if (tmp0->cmdInfo.optType == ASM_PUSHFD)
		{
			strcpy(cu->remark, "EFL");
			cu->value = pthread->context.EFlags;
		}
		//push 类型。获取第一个参数
		else
		{
			if (tmp0->cmdInfo.optType != ASM_PUSH)
			{
				return false;
			}

			if (tmp0->cmdInfo.op[0].opType&OP_MEM)
			{
				ulong v = 0;
				if (Readmemory(&v, tmp0->cmdInfo.op[0].opConst, 4, MM_RESILENT) != 4)
				{
					return false;
				}
				cu->value = v;
				//memory only ANTIDUMP
				strcpy(cu->remark, "ANTIDUMP");
			}
			else
			{
				if (cn->cmdInfo.op[0].opType&OP_IMM)
				{
					cu->value = cn->cmdInfo.op[0].opConst;
				}
				else
				{
					ulong regindex = RegType2RegIndex(cn->cmdInfo.op[0].reg);
					strcpy(cu->remark, GET_REG_KEY(regindex));
					cu->value = GetRegValue(pthread, regindex);
				}
			}
		}

	}
	return true;
}

bool VmpExplore::AnalyseContext()
{
	if (!_entryChain)
		return false;
	int i = 0;
	if (_contextCount == 0)
	{
		LOG(0, "VMP entry analyse context info failed! context count == 0", NULL, LOG_HILITE);
		return false;
	}


	while (i < _contextCount)
	{
		int cxtesp = (_contextCount - i)*(-4);
		Inst_UD_Node* tmp = _entryChain->GetTail();
		Inst_UD_Node* cxtNode = NULL;
		while (tmp)
		{
			if (!tmp->isDiscarded && tmp->espPosDef == cxtesp)
			{
				cxtNode = tmp;
				break;
			}
			tmp = tmp->preNode;
		}
		if (!cxtNode)
		{
			LOG(0, LSFI("VMP entry analyse context info failed1! offset:[%d]", i), NULL, LOG_HILITE);
			return false;
		}
		if (!GetContextByEspDef(cxtNode, &_context[i]))
		{
			LOG(0, LSFI("VMP entry analyse context info failed! offset2:[%d], ip[%08X]", i, cxtNode->cmdInfo.ip), NULL, LOG_HILITE);
			return false;
		}
		//first context must imm for "RElOC"
		if (!i)
		{
			if (_context[i].remark[0])
			{
				LOG(0, LSFI("VMP entry analyse context info failed! offset3:[%d], ip[%08X]", i, cxtNode->cmdInfo.ip), NULL, LOG_HILITE);
				return false;
			}
			else
			{
				strcpy(_context[i].remark, "RELOC");
			}
		}
		//除最后两个外都必须明确定义
		else if (i<_contextCount - 2)
		{
			if(!_context[i].remark[0])
			{
				LOG(0, LSFI("VMP entry analyse context info failed! offset3:[%d], ip[%08X]", i, cxtNode->cmdInfo.ip), NULL, LOG_HILITE);
				return false;
			}
		}
		//最后两个must imm
		else
		{
			if (_context[i].remark[0])
			{
				LOG(0, LSFI("VMP entry analyse context info failed! offset4:[%d], ip[%08X]", i, cxtNode->cmdInfo.ip), NULL, LOG_HILITE);
				return false;
			}

			if (i == _contextCount - 2)
			{
				strcpy(_context[i].remark, "RETADDR");
			}
			else
			{
				strcpy(_context[i].remark, "INITKEY");
			}
		}

		Quickinsertname(cxtNode->cmdInfo.ip, NM_COMMENT, LSFI("Push %s", _context[i].remark));
		i++;
	}
	
	
	return true;
}

bool VmpExplore::ReAnalyseDispatchInfo()
{
	code_handle* ch = CreateCodeHandle(&_handlerDecode, _dispatchInfo.idspReg, _dispatchInfo.idspReg);
	if (!ch)
	{
		return false;
	}
	simple_cmd_info* RegJoinCmd=NULL;
	ulong OpcodeJoinReg = _dispatchInfo.opcodeJoinReg;
	if (_dispatchInfo.opcodeJoinReg)
	{
		RegJoinCmd = new simple_cmd_info;
		*RegJoinCmd = *_dispatchInfo.opcodeDecode.header;
		RegJoinCmd->nextCmd = NULL;
		RegJoinCmd->preCmd = NULL;
	}

	simple_cmd_info* tmp = _dispatchInfo.opcodeDecode.tail;
	while (tmp)
	{
		Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, tmp->note);
		tmp = tmp->preCmd;
	}

	ulong tableBase = _dispatchInfo.tableBase;
	earseCmdGroup(&_dispatchInfo.opcodeDecode);
	memset(&_dispatchInfo, 0, sizeof(vmp_dispatch_info));
	_dispatchInfo.opcodeJoinReg = OpcodeJoinReg;

	for (ulong i = 0; i < VMP_HANDLER_DECODE_CONST; i++)
	{
		ulong v = 0;
		Inst_UD_Chain* chain = NULL;
		if (Readmemory(&v, tableBase + i * 4, 4, MM_RESILENT) != 4)
		{
			FreeCodeHandle(ch);
			LOG(0, LSFI("VMP reanalyse dispatch info falied! Readmemory error![index:%d]", i));
			return false;
		}
		ulong v0 = DoCodeHandle(ch, v);
		chain = ReadHandlerCmdChain(v0);
		if (_checkEsp.cmdInfo.ip)
		{
			//LOG(_checkEsp.cmdInfo.ip, _checkEsp.cmdInfo.cmd, _checkEsp.note);
			if (!AnalyseDispatchInfo(chain, false))
			{
				delete chain;
				FreeCodeHandle(ch);
				LOG(0, "VMP reanalyse dispatch info falied! Dispatch info get error!", NULL, LOG_HILITE);
				return false;
			}

			break;
		}
		delete chain;
	}

	if (!_checkEsp.cmdInfo.ip)
	{
		FreeCodeHandle(ch);
		LOG(0, "VMP reanalyse dispatch info falied! check esp not found!", NULL, LOG_HILITE);
		return false;
	}
	_dispatchInfo.opcodeLoadIP = _dispatchInfo.opcodeDecode.header->cmdInfo.ip;
	if (RegJoinCmd)
	{
		addCmdToGroupHeader(&_dispatchInfo.opcodeDecode, RegJoinCmd);
	}

	//if (!GetVMhandlerEntry(_checkEsp.cmdInfo.ip))
	if (!GetVMhandlerEntry(_dispatchInfo.dispatchCmd.cmdInfo.ip))
	{
		FreeCodeHandle(ch);
		LOG(0, "VMP reanalyse dispatch info falied! get vmhandler entry error!", NULL, LOG_HILITE);
		return false;
	}

	FreeCodeHandle(ch);
	return true;
}

bool VmpExplore::AnalyseHandlers()
{
	code_handle* ch = CreateCodeHandle(&_handlerDecode, _dispatchInfo.idspReg, _dispatchInfo.idspReg);
	if (!ch)
	{
		return false;
	}
	for (ulong i = 0; i <VMP_HANDLER_DECODE_CONST; i++)
	{
		ulong v = 0;

		if (Readmemory(&v, _dispatchInfo.tableBase + i * 4, 4, MM_RESILENT) != 4)
		{
			FreeCodeHandle(ch);
			LOG(0, LSFI("VMP handlers analyse falied! Readmemory error![index:%d]", i));
			return false;
		}
		ulong v0 = DoCodeHandle(ch, v);

		_handlers[i].orgData = v;
		_handlers[i].addr = v0;

		for (ulong j = 0; j < i; j++)
		{
			if (_handlers[i].addr == _handlers[j].addr)
			{
				_handlers[i].handlerChain = _handlers[j].handlerChain;
				_handlers[i].handler = _handlers[j].handler;
				_handlers[i].isCopy = true;
				break;
			}
		}
		if (_handlers[i].isCopy)
		{
			continue;
		}
		_handlers[i].handlerChain = ReadHandlerCmdChain(v0,false);
		if (_handlers[i].handlerChain)
		{
			_handlers[i].handler = VmpHandler::MatchHandler(_handlers[i].handlerChain);
			if (_handlers[i].handler)
			{
				//LOG(v0, LSFI("%02X  %08X->%08X", i, v, v0), VmpHandler::GetHandler((vm_handler)_handlers[i].handler));
			}
			else
			{
				
#if _DEBUG
				LOG(v0, LSFI("%02X  %08X->%08X", i, v, v0), "VM_Unknown",LOG_HILITE);
				_handlers[i].handlerChain->PrintChain(true);
#endif
			}

			///////
			//delete _handlers[i].handlerChain;
			//////
		}
		else
		{
			_handlers[i].handler = VM_Invalid;
		}
		vmp_handler_addr* vha = _handlersAddr[_handlers[i].handler];
		vmp_handler_addr* newvha = new vmp_handler_addr;
		memset(newvha, 0, sizeof(vmp_handler_addr));
		newvha->addr = _handlers[i].addr;
		newvha->chain = _handlers[i].handlerChain;
		newvha->next = NULL;
		newvha->esiChange = newvha->esiOffset = newvha->esiOffsetDigit = 0;
		
		if (VMPFindHandlerEsiOffset(newvha))
		{
			VMPGetHandlerDataDecode(newvha);
		}
		else if (_handlers[i].handler == VM_PopR32 || _handlers[i].handler == VM_PushR32)
		{
			newvha->DataLoad = newvha->chain->GetHeader();
			VMPGetHandlerDataDecode2(newvha);
		}
		VMPFindHandlerEsiEbpChange(newvha);
		if (vha)
		{
			while (vha->next)
			{
				vha = vha->next;
			}
			vha->next = newvha;
		}
		else
		{
			_handlersAddr[_handlers[i].handler] = newvha;
		}
	}

	FreeCodeHandle(ch);
	return true;
}

bool VmpExplore::AnalyseRetContext()
{
	if (!_handlersAddr[VM_Retn])
	{
		return false;
	}
	int cot = -1;
	Inst_UD_Node* tmp = _handlersAddr[VM_Retn]->chain->GetHeader();
	int espDefEspPos = 0;
	while (tmp)
	{
		if (tmp->opDef&ud_esp)
		{
			espDefEspPos = tmp->espPos;
			break;
		}
		tmp = tmp->nextNode;
	}
	while (tmp)
	{
		if (tmp->opRef&ud_esp)
		{

			if (tmp->cmdInfo.op[0].opType&OP_REG)
			{
				if ((tmp->espPosRef - espDefEspPos) / 4 > cot)
				{
					cot = max(cot, (tmp->espPosRef - espDefEspPos) / 4);
					strcpy_s(_retContext[(tmp->espPosRef - espDefEspPos) / 4].remark, GET_REG_KEY(RegType2RegIndex(tmp->cmdInfo.op[0].reg)));
				}
				else if (tmp->preNode->cmdInfo.optType == ASM_PUSH && tmp->preNode->cmdInfo.op[0].reg&ud_esp)
				{
					cot = max(cot, (tmp->preNode->espPosRef - espDefEspPos) / 4);
					strcpy_s(_retContext[(tmp->preNode->espPosRef - espDefEspPos) / 4].remark, GET_REG_KEY(RegType2RegIndex(tmp->preNode->cmdInfo.op[0].reg)));
				}
			}
			else if (tmp->cmdInfo.optType == ASM_POPFD)
			{
				if ((tmp->espPosRef - espDefEspPos) / 4 > cot)
				{
					cot = max(cot, (tmp->espPosRef - espDefEspPos) / 4);
					strcpy_s(_retContext[(tmp->espPosRef - espDefEspPos) / 4].remark, "EFL");
				}
				else if (tmp->preNode->cmdInfo.optType == ASM_PUSH && tmp->preNode->cmdInfo.op[0].reg&ud_esp)
				{
					cot = max(cot, (tmp->preNode->espPosRef - espDefEspPos) / 4);
					strcpy_s(_retContext[(tmp->preNode->espPosRef - espDefEspPos) / 4].remark, "EFL");
				}
			}

		}
		tmp = tmp->nextNode;
	}
	_retContext[cot].value = 1;
	for (int i = cot-1; i >= 0; i--)
	{
		_retContext[i].value = 1;
		for (int j = i + 1; j <= cot; j++)
		{
			if (strcmp(_retContext[i].remark, _retContext[j].remark)==0)
			{
				_retContext[i].remark[0] = 0;
			}
		}
	}
	return true;
}


bool VmpExplore::AnalyseEntryCode()
{
	simple_cmd_group entryEsiDecode;
	memset(&entryEsiDecode, 0, sizeof(simple_cmd_group));
	simple_cmd_info* tmp = _initkeyInfo.initkeyDecode.header;
	while (tmp)
	{
		if (strcmp(tmp->note, "InitKey Decode") == 0)
		{
			simple_cmd_info * cmdinfo = new simple_cmd_info;
			memset(cmdinfo, 0, sizeof(simple_cmd_info));
			cmdinfo->cmdInfo = tmp->cmdInfo;
			strcpy(cmdinfo->note, tmp->note);
			addCmdToGroupHeader(&entryEsiDecode, cmdinfo);
		}
		tmp = tmp->nextCmd;
	}
	code_handle* ch = CreateCodeHandle(&entryEsiDecode, _initkeyInfo.initkeyDecodeReg, _initkeyInfo.initkeyDecodeReg);
	if (!ch)
	{
		return false;
	}

	ulong initkey=DoCodeHandle(ch,_context[_contextCount-1].value);
	FreeCodeHandle(ch);
	earseCmdGroup(&entryEsiDecode);
	VmpAnalyseCode(initkey + _context[0].value, initkey);
	return true;
}


bool VmpExplore::VMPFindHandlerEsiOffset(vmp_handler_addr* vmhAddr)
{
	if (!vmhAddr->chain)
	{
		return false;
	}
	Inst_UD_Node* tmp = vmhAddr->chain->GetHeader();
	while (tmp)
	{
		if (tmp->cmdInfo.ip == _dispatchInfo.opcodeLoadIP)
		{
			break;
		}
		if (tmp->cmdInfo.optType!=ASM_LEA && tmp->cmdInfo.op[1].opType&OP_MEM && tmp->cmdInfo.op[1].reg == ud_esi && tmp->cmdInfo.op[0].reg != ud_esi)
		{
			vmhAddr->DataLoad = tmp;
			vmhAddr->esiOffset=tmp->cmdInfo.op[1].opConst;
			vmhAddr->esiOffsetDigit = tmp->cmdInfo.op[1].opType&0xFFFF0000;
			return true;
		}
		tmp = tmp->nextNode;
	}
	return false;
}

bool VmpExplore::VMPFindHandlerEsiEbpChange(vmp_handler_addr* vmhAddr)
{
	if (!vmhAddr->chain)
	{
		return false;
	}
	Inst_UD_Node* tmp = vmhAddr->chain->GetHeader();
	while (tmp)
	{
		if (tmp->cmdInfo.ip == _dispatchInfo.opcodeLoadIP)
		{
			break;
		}
		if (tmp->cmdInfo.op[0].opType&OP_REG && tmp->cmdInfo.op[0].reg == ud_esi)
		{
			switch (tmp->cmdInfo.optType)
			{
			case ASM_INC:
				vmhAddr->esiChange += 1;
				break;
			case ASM_DEC:
				vmhAddr->esiChange += (-1);
				break;
			case ASM_LEA:
				if (tmp->cmdInfo.op[1].reg == ud_esi)
				{
					vmhAddr->esiChange += tmp->cmdInfo.op[1].opConst;
				}
				break;
			case ASM_ADD:
				if (tmp->cmdInfo.op[1].opType&OP_IMM)
				{
					vmhAddr->esiChange += tmp->cmdInfo.op[1].opConst;
				}
				break;
			case ASM_SUB:
				if (tmp->cmdInfo.op[1].opType&OP_IMM)
				{
					vmhAddr->esiChange += (-(int)tmp->cmdInfo.op[1].opConst);
				}
				break;
			default:
				break;
			}
		}
		else if (tmp->cmdInfo.op[0].opType&OP_REG && tmp->cmdInfo.op[0].reg == ud_ebp)
		{
			switch (tmp->cmdInfo.optType)
			{
			case ASM_INC:
				vmhAddr->ebpChange += 1;
			case ASM_DEC:
				vmhAddr->ebpChange += (-1);
			case ASM_LEA:
				if (tmp->cmdInfo.op[1].reg == ud_ebp)
				{
					vmhAddr->ebpChange += tmp->cmdInfo.op[1].opConst;
				}
				break;
			case ASM_ADD:
				if (tmp->cmdInfo.op[1].opType&OP_IMM)
				{
					vmhAddr->ebpChange += tmp->cmdInfo.op[1].opConst;
				}
				break;
			case ASM_SUB:
				if (tmp->cmdInfo.op[1].opType&OP_IMM)
				{
					vmhAddr->ebpChange += (-(int)tmp->cmdInfo.op[1].opConst);
				}
				break;
			default:
				break;
			}
		}
		tmp = tmp->nextNode;
	}
	return true;
}
bool VmpExplore::VMPGetHandlerDataDecode2(vmp_handler_addr* vmhAddr)
{
	Inst_UD_Node* tmp = vmhAddr->DataLoad->nextNode;
	ulong udReg = RegIndex2RegType(_dispatchInfo.indexReg);
	ulong udReg0 = RegIndex2RegType(_dispatchInfo.opcodeJoinReg);
	while (tmp)
	{
		if (tmp->cmdInfo.op[0].reg==(ud_edi | ud_eax) || tmp->cmdInfo.op[1].reg==(ud_edi | ud_eax))
		{
			break;
		}
		if (tmp->opDef&udReg)
		{
			addCmdToGroup(&vmhAddr->dataDecode, createCmdFromUDNode(tmp, "Data Decode"));
			Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, "Data Decode");
		}
		else if (tmp->opDef&udReg0)
		{
			addCmdToGroup(&vmhAddr->dataDecode, createCmdFromUDNode(tmp, "Join Reg Do"));
			Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, "Join Reg Do");
			break;
		}
		tmp = tmp->nextNode;
	}
	return true;
}
bool VmpExplore::VMPGetHandlerDataDecode(vmp_handler_addr* vmhAddr)
{
	Inst_UD_Node* tmp = vmhAddr->DataLoad->nextNode;
	ulong udReg = RegIndex2RegType(_dispatchInfo.indexReg);
	ulong udReg0 = RegIndex2RegType(_dispatchInfo.opcodeJoinReg);
	while (tmp)
	{
		if (tmp->cmdInfo.ip == _dispatchInfo.opcodeLoadIP)
		{
			break;
		}
		if (tmp->opDef&udReg)
		{
			addCmdToGroup(&vmhAddr->dataDecode, createCmdFromUDNode(tmp, "Data Decode"));
			Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, "Data Decode");
		}
		else if (tmp->opDef&udReg0)
		{
			addCmdToGroup(&vmhAddr->dataDecode, createCmdFromUDNode(tmp, "Join Reg Do"));
			Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, "Join Reg Do");
			break;
		}
		tmp = tmp->nextNode;
	}
	return true;
}


ulong VmpExplore::GetStartAddress()
{
	if (_entryChain)
	{
		return _entryChain->GetHeader()->cmdInfo.ip;
	}
	return 0;
}

void VmpExplore::PrintVMPInfo()
{
	PrintInitkeyInfo();
	PrintContext();
	PrintDispatchInfo();
	PrintHandlerDecode();
	PrintCheckEsp();
	PrintVMEntry();
	PrintHandlers();
	PrintHandlersAddr();
	PrintRetContext();
}

void VmpExplore::PrintInitkeyInfo()
{
	
	LOGTITLE("VMP Initkey Info:");
	LOG(0, "InitKey:",LSFI("%08X",_initkeyInfo.initkeyValue));
	LOG(0, "InitKey Decode Reg:", GET_REG_KEY(_initkeyInfo.initkeyDecodeReg));
	LOG(0, "Reloc Join Reg:", GET_REG_KEY(_initkeyInfo.relocJoinReg));
	LOGTITLEEND;
	LOGTITLE("VMP Initkey Decode:");
	simple_cmd_info* tmp = _initkeyInfo.initkeyDecode.header;
	while (tmp)
	{

		LOG(tmp->cmdInfo.ip,tmp->cmdInfo.cmd,tmp->note);
		Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, tmp->note);
		tmp = tmp->nextCmd;
	}
	LOGTITLEEND;
}

void VmpExplore::PrintDispatchInfo()
{
	
	LOGTITLE("VMP Opcode Decode:");
	simple_cmd_info* tmp = _dispatchInfo.opcodeDecode.header;
	while (tmp)
	{
		LOG(tmp->cmdInfo.ip,tmp->cmdInfo.cmd, tmp->note);
		Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, tmp->note);
		tmp = tmp->nextCmd;
	}


	LOGTITLEEND;
	LOGTITLE("VMP Dispatch Info:");

	LOG(_dispatchInfo.dispatchCmd.cmdInfo.ip, "Command:", _dispatchInfo.dispatchCmd.cmdInfo.cmd);
	Quickinsertname(_dispatchInfo.dispatchCmd.cmdInfo.ip, NM_COMMENT, "Dispatch Cmd");
	LOG(_dispatchInfo.tableBase, "Table Base:",LSFI("%08X", _dispatchInfo.tableBase));
	Quickinsertname(_dispatchInfo.tableBase, NM_LABEL, "VMHandlerTable");
	LOG(0, "Dispatch Reg:",GET_REG_KEY(_dispatchInfo.idspReg));
	LOG(0, "Index Reg:", GET_REG_KEY(_dispatchInfo.indexReg));

	LOG(0, "Opcode Decode Reg:", GET_REG_KEY(_dispatchInfo.opcodeDecodeReg));
	if (_dispatchInfo.opcodeJoinReg != -1)
		LOG(0,"Join Decode Reg:", GET_REG_KEY(_dispatchInfo.opcodeJoinReg));
	LOG(0, "ESI offset:", LSFN("%d", _dispatchInfo.esiOffset));
	LOG(0, "ESI change:", LSFN("%d", _dispatchInfo.esiChange));
	LOGTITLEEND;
}

void VmpExplore::PrintHandlerDecode()
{
	
	LOGTITLE("VMP Handler Decode:");
	simple_cmd_info* tmp = _handlerDecode.tail;
	while (tmp)
	{
		LOG(tmp->cmdInfo.ip, tmp->cmdInfo.cmd,tmp->note);
		Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, tmp->note);
		tmp = tmp->preCmd;
	}
	LOGTITLEEND;
}

void VmpExplore::PrintCheckEsp()
{
	
	LOGTITLE("VMP Check ESP:");
	LOG(_checkEsp.cmdInfo.ip, _checkEsp.cmdInfo.cmd, _checkEsp.note);
	Quickinsertname(_checkEsp.cmdInfo.ip, NM_COMMENT, _checkEsp.note);
	LOGTITLEEND;
}

void VmpExplore::PrintContext()
{
	
	LOGTITLE("VMP Context:");
	for (int i = 0; i < _contextCount; i++)
	{
		LOG(0,LSFI("%02d (+%02X)  %s",i, i * 4, _context[i].remark), LSFN("%08X",_context[i].value));
	}
	LOGTITLEEND;
}

void VmpExplore::PrintRetContext()
{
	LOGTITLE("VMP Retn Context:");
	for (int i = 0;_retContext[i].value; i++)
	{
		LOG(0, LSFI("%02d (+%02X)",i, i * 4), _retContext[i].remark[0] ? _retContext[i].remark : "-");
	}
	LOGTITLEEND;
}

void VmpExplore::PrintVMEntry()
{
	LOGTITLE("VMP Entry:");
	simple_cmd_info* tmp = _vmEntry.header;
	while (tmp)
	{
		LOG(tmp->cmdInfo.ip, tmp->cmdInfo.cmd, tmp->note);
		Quickinsertname(tmp->cmdInfo.ip, NM_COMMENT, tmp->note);
		tmp = tmp->nextCmd;
	}

	LOGTITLEEND;
}

void VmpExplore::PrintHandlers()
{
	
	LOGTITLE("VMP Handlers:");
	for (ulong i = 0; i < VMP_HANDLER_DECODE_CONST;i++)
	{
		LOG(_handlers[i].addr, LSFI("%02X  %08X->%08X", i, _handlers[i].orgData, _handlers[i].addr),
			VmpHandler::GetHandler((vm_handler)_handlers[i].handler));
	}
	LOGTITLEEND;
}

void VmpExplore::PrintHandlersAddr()
{
	
	LOGTITLE("VMP Handlers Address:");
	for (ulong i = 0; i < VMH_End; i++)
	{
		vmp_handler_addr* tmp = _handlersAddr[i];
		if (i != VM_Invalid && tmp)
		{
			while (tmp)
			{
				char* name = (char*)VmpHandler::GetHandler((vm_handler)i);
				LOG(tmp->addr, name, 
					tmp->esiOffsetDigit?
					LSFN("ESIOffset:%d, ESIChange:%d, EBPChange:%d, OpSize:%d", tmp->esiOffset,tmp->esiChange,tmp->ebpChange,tmp->esiOffsetDigit>>16)
					: LSFN("EBPChange:%d", tmp->ebpChange));
				Quickinsertname(tmp->addr, NM_COMMENT, name);
				Quickinsertname(tmp->addr, NM_LABEL, name);
				tmp = tmp->next;
			}
		}
	}
	LOGTITLEEND;
}

#define CODE_PUSH_REG     0x50
#define CODE_PUSH_IMM32   0x68
#define CODE_POP_REG      0x58
#define CODE_POP_MEM	  0x058F
#define CODE_PUSHAD		  0x60
#define CODE_PUSHFD       0x9C
#define CODE_POPAD        0x61
#define CODE_POPFD        0x9D
#define CODE_RET          0xC3

code_handle* VmpExplore::CreateCodeHandle(simple_cmd_group* cmdGroup, ulong inReg, ulong outReg)
{
	if (!cmdGroup->header)
	{
		return NULL;
	}
	code_handle* ret = new code_handle;
	ret->baseAddr= VirtualAlloc(NULL, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!ret->baseAddr)
	{
		delete ret;
		return NULL;
	}

	unsigned char* codeBuf = (unsigned char*)ret->baseAddr;
	*(codeBuf++) = CODE_PUSHAD;		//pushad
	*(codeBuf++) = CODE_PUSHFD;		//pushfd
	*(codeBuf++) = CODE_PUSH_IMM32; //push imm

	ret->inOffset = (ulong)codeBuf - (ulong)ret->baseAddr;

	*(codeBuf++) = 0; //imm
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;


	*(codeBuf++) = CODE_POP_REG + (unsigned char)inReg;//pop in reg
	simple_cmd_info* tmp = cmdGroup->tail;

	while (tmp)//add code
	{
		memcpy(codeBuf, tmp->cmdInfo.cmdBuf, tmp->cmdInfo.cmdLen);
		codeBuf += tmp->cmdInfo.cmdLen;
		tmp = tmp->preCmd;
	}

	*(codeBuf++) = CODE_PUSH_REG + (unsigned char)outReg;//push out reg
	*((USHORT*)codeBuf) = CODE_POP_MEM;//pop out value

	
	codeBuf += 2;
	ret->outOffset = (ulong)codeBuf - (ulong)ret->baseAddr;

	*(codeBuf++) = 0; //imm
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = CODE_POPFD;		//popfd
	*(codeBuf++) = CODE_POPAD;		//popad
	*(codeBuf++) = CODE_RET;		//ret
	return ret;
}

code_handle* VmpExplore::CreateCodeHandle2(simple_cmd_info* inst, ulong Reg1, ulong Reg2)
{
	if (!inst)
	{
		return NULL;
	}
	code_handle* ret = new code_handle;
	ret->baseAddr = VirtualAlloc(NULL, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!ret->baseAddr)
	{
		delete ret;
		return NULL;
	}

	unsigned char* codeBuf = (unsigned char*)ret->baseAddr;
	*(codeBuf++) = CODE_PUSHAD;		//pushad
	*(codeBuf++) = CODE_PUSHFD;		//pushfd
	*(codeBuf++) = CODE_PUSH_IMM32; //push imm

	ret->inOffset = (ulong)codeBuf - (ulong)ret->baseAddr;

	*(codeBuf++) = 0; //imm
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;

	*(codeBuf++) = CODE_POP_REG + (unsigned char)Reg1;//pop in reg

	//2
	*(codeBuf++) = CODE_PUSH_IMM32; //push imm
	ret->inOffset2 = (ulong)codeBuf - (ulong)ret->baseAddr;

	*(codeBuf++) = 0; //imm
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;


	*(codeBuf++) = CODE_POP_REG + (unsigned char)Reg2;//pop in reg

	simple_cmd_info* tmp = inst;

	while (tmp)//add code
	{
		memcpy(codeBuf, tmp->cmdInfo.cmdBuf, tmp->cmdInfo.cmdLen);
		codeBuf += tmp->cmdInfo.cmdLen;
		tmp = tmp->nextCmd;
	}

	*(codeBuf++) = CODE_PUSH_REG + (unsigned char)Reg1;//push out reg
	*((USHORT*)codeBuf) = CODE_POP_MEM;//pop out value


	codeBuf += 2;
	ret->outOffset = (ulong)codeBuf - (ulong)ret->baseAddr;

	*(codeBuf++) = 0; //imm
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	//
	*(codeBuf++) = CODE_PUSH_REG + (unsigned char)Reg2;//push out reg
	*((USHORT*)codeBuf) = CODE_POP_MEM;//pop out value

	codeBuf += 2;
	ret->outOffset2 = (ulong)codeBuf - (ulong)ret->baseAddr;

	*(codeBuf++) = 0; //imm
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;
	*(codeBuf++) = 0;

	*(codeBuf++) = CODE_POPFD;		//popfd
	*(codeBuf++) = CODE_POPAD;		//popad
	*(codeBuf++) = CODE_RET;		//ret
	return ret;
}

void VmpExplore::FreeCodeHandle(code_handle* ch)
{
	VirtualFree(ch->baseAddr, 0, MEM_RELEASE);
	delete ch;
}

ulong VmpExplore::DoCodeHandle(code_handle* ch, ulong dataIn)
{

	ulong ret=0;
	*((ULONG*)((ulong)ch->baseAddr + ch->inOffset)) = dataIn;
	*((ULONG*)((ulong)ch->baseAddr + ch->outOffset)) = (ULONG)(&ret);
	PF pf= (PF)ch->baseAddr;
	pf();
	return ret;
}

void VmpExplore::DoCodeHandle2(code_handle* ch, ulong dataIn, ulong dataIn2, ulong*dataOut, ulong*dataOut2)
{
	*((ULONG*)((ulong)ch->baseAddr + ch->inOffset)) = dataIn;
	*((ULONG*)((ulong)ch->baseAddr + ch->inOffset2)) = dataIn2;
	*((ULONG*)((ulong)ch->baseAddr + ch->outOffset)) = (ulong)dataOut;
	*((ULONG*)((ulong)ch->baseAddr + ch->outOffset2)) = (ulong)dataOut2;
	PF pf = (PF)ch->baseAddr;
	pf();
}

/*
bool VmpExplore::VmpPatchHash()
{
	_patchHashData.addr_MapViewOfFile = _GNAPI("MapViewOfFile","kernel32.dll");
	if (!_patchHashData.addr_MapViewOfFile)
	{
		LOGERROR("VMP patch hash get MapViewOfFile address error!");
		return false;
	}
	LOG(_patchHashData.addr_MapViewOfFile, "MapViewOfFile Address", LSFN("%08X", _patchHashData.addr_MapViewOfFile));
	_patchHashData.addr_GetHash = (_handlersAddr[VM_GetHash] ? _handlersAddr[VM_GetHash]->addr:0);
	if (!_patchHashData.addr_GetHash)
	{
		LOGERROR("VMP patch hash get VM_GetHash address error!");
		return false;
	}
	LOG(_patchHashData.addr_GetHash, "VM_GetHash Address", LSFN("%08X", _patchHashData.addr_GetHash));
	_patchHashData.addr_ReadDs32 = (_handlersAddr[VM_ReadDs32] ? _handlersAddr[VM_ReadDs32]->addr : 0);
	if (!_patchHashData.addr_ReadDs32)
	{
		LOGERROR("VMP patch hash get VM_ReadDs32 address error!");
		return false;
	}
	LOG(_patchHashData.addr_ReadDs32, "VM_ReadDs32 Address", LSFN("%08X", _patchHashData.addr_ReadDs32));

	//_BP(_patchHashData.addr_MapViewOfFile);
	//_RUN();
	LOGTITLE("VMP Patch Hash Info:");
	return true;
}


enum vmp_patch_hash_progress
{
	vmp_patch_hash_start = 1,
	vmp_patch_hash_to_mapviewoffile,
	vmp_patch_hash_to_mapviewoffile_and,
	vmp_patch_hash_file_hash,

	vmp_patch_hash_end = 0
};


bool VmpExplore::Do_VmpPatchHash(DEBUG_EVENT *debugevent)
{
	switch (_patchHashData.progress)
	{
	case vmp_patch_hash_start:
	{

		break;
	}
	case vmp_patch_hash_to_mapviewoffile:
	{
		if (_GR(REG_EIP) != _patchHashData.addr_MapViewOfFile)
		{
			LOGERROR("Do_VmpPatchHash error!");
			LOGTITLEEND;
			return true;
		}
		_BC(_patchHashData.addr_MapViewOfFile);
		_RTR();
		_patchHashData.progress++;
		break;
	}
	case vmp_patch_hash_to_mapviewoffile_and:
	{
		_patchHashData.fileMapAddr = _GR(REG_EAX);
		LOG(0, "File Map Address", LSFN("%08X", _patchHashData.fileMapAddr));
		_BP(_patchHashData.addr_ReadDs32);
		_RUN();
		_patchHashData.progress++;
		break;
	}
	case vmp_patch_hash_file_hash:
	{
		break;
	}
	case vmp_patch_hash_end:
	{
		LOGTITLEEND;
		return true;
	}
	default:
		break;
	}
	
	return false;
}*/

bool VmpExplore::VmpPatchHash()
{

	ulong addr_GetHash = (_handlersAddr[VM_GetHash] ? _handlersAddr[VM_GetHash]->addr : 0);
	if (!addr_GetHash)
	{
		//LOGERROR("VMP patch hash get VM_GetHash address error! It's a no hash check file.");
		MessageBox(NULL, "This is a no hash check file.", "Info", MB_OK | MB_ICONINFORMATION);
		return false;
	}
	ulong addr_ReadDs32 = (_handlersAddr[VM_ReadDs32] ? _handlersAddr[VM_ReadDs32]->addr : 0);
	if (!addr_ReadDs32)
	{
		LOGERROR("VMP patch hash get VM_ReadDs32 address error!");
		return false;
	}
	ulong addr_PopR32 = (_handlersAddr[VM_PopR32] ? _handlersAddr[VM_PopR32]->addr : 0);
	if (!addr_PopR32)
	{
		LOGERROR("VMP patch hash get VM_PopR32 address error!");
		return false;
	}
	ulong addr_Retn = (_handlersAddr[VM_Retn] ? _handlersAddr[VM_Retn]->addr : 0);
	if (!addr_Retn)
	{
		LOGERROR("VMP patch hash get VM_Retn address error!");
		return false;
	}
	ulong addr_Rdtsc = (_handlersAddr[VM_Rdtsc] ? _handlersAddr[VM_Rdtsc]->addr : 0);
	if (!addr_Rdtsc)
	{
		LOGERROR("VMP patch hash get VM_Rdtsc address error!");
		return false;
	}
	HANDLE hProcess = (HANDLE)Plugingetvalue(VAL_HPROCESS);
	ulong lpBuf = (ulong)VirtualAllocEx(hProcess, NULL, VMP_PATCH_HASH_DATA_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpBuf)
	{
		LOGERROR("VMP patch hash error! alloc remote mem error!");
		return false;
	}
	if (Writememory(&addr_GetHash, lpBuf, 4, MM_RESILENT) != 4 ||
		Writememory(&addr_ReadDs32, lpBuf + 4, 4, MM_RESILENT) != 4 ||
		Writememory(&addr_PopR32, lpBuf + 8, 4, MM_RESILENT) != 4 ||
		Writememory(&addr_Retn, lpBuf + 12, 4, MM_RESILENT) != 4 ||
		Writememory(&addr_Rdtsc, lpBuf + 16, 4, MM_RESILENT) != 4 ||
		Writememory(&_dispatchInfo.opcodeLoadIP, lpBuf + 20, 4, MM_RESILENT) != 4)
	{
		LOGERROR("VMP patch hash error! write mem error!");
		return false;
	}
	_patchHashDataAddr = lpBuf;
	HMODULE hModule=GetModuleHandle("OoWoodOne.dll");
	HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(IDR_VMP_GET_PATCH_INFO), TEXT("OSC"));
	if (NULL == hRsrc)
	{
		LOGERROR("VMP patch hash error! read resource error0!");
		return false;
	}
	DWORD dwSize = SizeofResource(hModule, hRsrc);
	if (0 == dwSize)
	{
		LOGERROR("VMP patch hash error! read resource error1!");
		return false;
	}
	HGLOBAL hGlobal = LoadResource(hModule, hRsrc);
	if (NULL == hGlobal)
	{
		LOGERROR("VMP patch hash error! read resource error2!");
		return false;
	}
	LPVOID pBuffer = LockResource(hGlobal);
	if (NULL == pBuffer)
	{
		LOGERROR("VMP patch hash error! read resource error3!");
		return false;
	}
	char* curdir = (char*)Plugingetvalue(VAL_CURRENTDIR);
	if (!curdir)
	{
		LOGERROR("VMP patch hash error! get dir error3!");
		return false;
	}
	char path[MAX_PATH];
	GetTempPath(MAX_PATH, path);
	strcat_s(path, "/VMP_Get_Hash_Info.osc");
	HANDLE hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL
		, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
	{
		LOGERROR("VMP patch hash error! create file error!");
		return false;
	}
	ulong wsize = 0;
	if (!WriteFile(hFile, pBuffer, dwSize, &wsize, NULL))
	{
		CloseHandle(hFile);
		LOGERROR("VMP patch hash error! write file error0!");
		return false;
	}
	char* inputstr = LSFI("\r\nMOV Data_Buffer,%08X\r\nRET", lpBuf);
	if (!WriteFile(hFile, inputstr, strlen(inputstr), &wsize, NULL))
	{
		CloseHandle(hFile);
		LOGERROR("VMP patch hash error! write file error1!");
		return false;
	}
	CloseHandle(hFile);

	HMODULE hMod = GetModuleHandle("ODbgScript.dll");
	if (hMod) // 检测是否被其他插件加载
	{
		int(*pFunc)(char*) = (int(*)(char*)) GetProcAddress(hMod, "ExecuteScript");
		if (pFunc) // 检查是否获得输出函数
		{
			pFunc(path); // 执行输出函数
		}
		else
		{
			LOGERROR("VMP patch hash error! ODbgScript.dll&ExecuteScript not found!");
			return false;
		}
	}
	else
	{
		LOGERROR("VMP patch hash error! module ODbgScript.dll not found!");
		return false;
	}
	DeleteFile(path);
	return true;
}


//////////////////////////////////////////////////////////////////////////

/*  vmp patch hash shell code
;-------------------------------return---------------------------------
@HashJmpRetn:;		+0x0
jmp 0
@ReadDs32JmpRetn:;	+0x5
jmp 0
@RdtscJmpRetn:;		+0xA
jmp 0
nop

;-------------------------------data-----------------------------------
dd 0 ;reloc				+0x10
dd 0;NowEip				+0x14
dd 0;NowHashValue		+0x18
dd 0;NowTableValue		+0x1C
dd 0;ReadDs32 offset		+0x20
dd 0;ReadDs32 data		+0x24
dd 0;ReadDs32 orgdata1	+0x28
dd 0;ReadDs32 orgdata1	+0x2C
dd 0;HashEspChange		+0x30
dd 0;Rdtsc eax			+0x34
dd 0;Rdtsc edx			+0x38
dd 0;reserve

;-------------------------------entry---------------------------
@HashPatchEntry:;		+0x40
jmp @PatchHash
@ReadDs32PatchEntry:;	+0x45
jmp @PatchReadDs32
@RdtscPatchEntry:;		+0x4A
jmp @PatchRdtsc
nop
dd 0 0 0 0;reserve
;-----------------------------rdtsc org cmd----------------------
@RdtscOrgCmd:
dd 90909090 90909090 90909090 90909090;+0x60
nop
nop
nop
jmp @RdtscJmpRetn
;-------------------------get data base--------------------------
@GetDataBase:;		+0x78
call @GetIP
@GetIP:
pop eax;				+0x7D
sub eax,0x7D
ret

;-------------------------patch hash------------------------------
nop
nop				;patch hash
@PatchHash:
pushad
call @GetDataBase
mov edx,eax
mov ecx,edx
sub ecx,[edx+0x10]		;get module base
cmp [edx+0x14],esi		;vmeip equal
je short @PatchHashEnd
lea eax,[edx+0x200]		;hash data offset
sub eax,14

@PatchHashFindLoop:
add eax,14
cmp dword ptr[eax],0
je short @PatchHashEnd
mov ebx,[eax]			;get hash vmeip
add ebx,ecx			;add reloc
cmp ebx,esi
jne @PatchHashFindLoop
push [eax]
add [esp],ecx			;add reloc
pop [edx+0x14]		;pop new vmeip
push [eax+0x4]
pop [edx+0x18]		;pop new hash value
push [eax+0x10]
pop [edx+0x1C]		;pop new table value

@PatchHashEnd:
mov eax,[edx+0x20]	;get ReadDs32 offset
add eax,ecx			;add reloc
mov byte ptr[eax],0xE9	;"jmp"
inc eax
push [edx+0x24]
pop [eax]			;pop jmp addr
mov eax,[edx+0x18]
mov [ebp+4],eax		;modify hash value
popad
add ebp,4			;vmp pop
call @GetDataBase
sub esp,[eax+0x30]	;change esp
jmp @HashJmpRetn

;-------------------------------patch ReadDs32--------------------------
nop
nop				;patch ReadDs32
@PatchReadDs32:
pushad
call @GetDataBase
mov edx,eax
mov ecx,edx
sub ecx,[edx+0x10]		;get module base
mov eax,[edx+0x1C]
cmp eax,0
je @OrgReadDs32
mov [ebp],eax				;patch table value
jmp @PatchReadDs32End
@OrgReadDs32:
mov eax,[ebp]
mov eax,[eax]
mov [ebp],eax
@PatchReadDs32End:
mov eax,[edx+0x20]		;get ReadDs32 offset
add eax,ecx				;add reloc
push [edx+0x28]
pop [eax]				;pop org data1
push [edx+0x2C]
pop [eax+4]				;pop org data2
popad
call @GetDataBase
sub esp,[eax+0x30]		;change esp
jmp @ReadDs32JmpRetn

;-------------------------------patch rdtsc value----------------------
nop
nop				;patch rdtsc value
@PatchRdtsc:
call @GetDataBase
mov edx,eax
push [edx+0x34]
pop eax
push [edx+0x38]
pop edx
jmp @RdtscOrgCmd


*/

char __VMPPatchHashShellCode[] = "\xE9\xFB\xFF\xE4\xFF\xE9\xF6\xFF\xE4\xFF\xE9\xF1\xFF\xE4\xFF\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\xE9\x3F\x00\x00\x00\xE9\xA4\x00\x00\x00\xE9\xE8\x00\x00\x00\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\xE9\x92\xFF\xFF\xFF\xE8\x00\x00\x00\x00\x58\x83\xE8"
"\x7D\xC3\x90\x90\x60\xE8\xEE\xFF\xFF\xFF\x8B\xD0\x8B\xCA\x2B\x4A\x10\x39\x72\x14\x74\x31\x8D\x82\x00\x02\x00\x00\x83\xE8\x14\x83"
"\xC0\x14\x83\x38\x00\x74\x20\x8B\x18\x03\xD9\x3B\xDE\x0F\x85\xEC\xFF\xFF\xFF\xFF\x30\x01\x0C\x24\x8F\x42\x14\xFF\x70\x04\x8F\x42"
"\x18\xFF\x70\x10\x8F\x42\x1C\x8B\x42\x20\x03\xC1\xC6\x00\xE9\x40\xFF\x72\x24\x8F\x00\x8B\x42\x18\x89\x45\x04\x61\x83\xC5\x04\xE8"
"\x94\xFF\xFF\xFF\x2B\x60\x30\xE9\x14\xFF\xFF\xFF\x90\x90\x60\xE8\x84\xFF\xFF\xFF\x8B\xD0\x8B\xCA\x2B\x4A\x10\x8B\x42\x1C\x83\xF8"
"\x00\x0F\x84\x08\x00\x00\x00\x89\x45\x00\xE9\x08\x00\x00\x00\x8B\x45\x00\x8B\x00\x89\x45\x00\x8B\x42\x20\x03\xC1\xFF\x72\x28\x8F"
"\x00\xFF\x72\x2C\x8F\x40\x04\x61\xE8\x4B\xFF\xFF\xFF\x2B\x60\x30\xE9\xD0\xFE\xFF\xFF\x90\x90\xE8\x3C\xFF\xFF\xFF\x8B\xD0\xFF\x72"
"\x34\x58\xFF\x72\x38\x5A\xE9\x15\xFF\xFF\xFF";

#define __HashDataOffset		0x200
#define __EspChangeDataOffset	0x800
#define __CheckVMOffset			0x804
#define __RdtscEaxOffset		0x808
#define __RdtscEdxOffset		0x80C
#define __HashJmpRetn			0x0
#define __ReadDs32JmpRetn		0x5
#define __RdtscJmpRetn			0xA
#define __Reloc					0x10
#define __NowEip				0x14
#define __NowHashValue			0x18
#define __NowTableValue			0x1C
#define __ReadDs32Offset		0x20
#define __ReadDs32Data			0x24
#define __ReadDs32OrgData1		0x28
#define __ReadDs32OrgData2		0x2C
#define __HashEspChange			0x30
#define __RdtscEax				0x34
#define __RdtscEdx				0x38
#define __HashPatchEntry		0x40
#define __ReadDs32PatchEntry	0x45
#define __RdtscPatchEntry		0x4A
#define __RdtscOrgCmd			0x60




bool VmpExplore::Do_VmpPatchHash()
{
	if (Getstatus() == STAT_RUNNING)
	{
		return false;
	}

	char* outData = (char*)VirtualAlloc(NULL, VMP_PATCH_HASH_DATA_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!outData)
	{
		LOGERROR("VMP get patch info error! alloc error!");
		return false;
	}
	
	if (Readmemory(outData, _patchHashDataAddr, VMP_PATCH_HASH_DATA_SIZE, MM_RESILENT) != VMP_PATCH_HASH_DATA_SIZE)
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		LOGERROR("VMP get patch info error! read data error!");
		return false;
	}
	
	hash_info* hashinfos = (hash_info*)((ULONG)outData + __HashDataOffset);
	LOGTITLE("VMP Hash Data:");

	char* filename = (char*)Plugingetvalue(VAL_EXEFILENAME);
	char newFileName[MAX_PATH];
	char extName[10];
	extName[0] = 0;
	strcpy_s(newFileName, filename);
	char* tmp = &newFileName[strlen(newFileName) - 1];
	while (tmp > newFileName && *tmp != '.')
	{
		tmp--;
	}
	if (tmp != newFileName)
	{
		strcpy_s(extName, tmp);
		*tmp = 0;
	}
	strcat_s(newFileName, "_PatchHash");
	strcat_s(newFileName, extName);
	
	if (!CopyFile(filename, newFileName, false))
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		LOGERROR("VMP get patch info error! copy file failed!");
		return false;
	}
	
	HANDLE hFile = CreateFileA(newFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		LOGERROR("VMP get patch info error! open file failed!");
		return false;
	}
	ulong i = 0;
	
	//patch hash entry
	ulong addr_GetHash = (_handlersAddr[VM_GetHash] ? _handlersAddr[VM_GetHash]->addr : 0);
	t_module* module = Findmodule(addr_GetHash);
	if (!module)
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		CloseHandle(hFile);
		LOGERROR("VMP get patch info error! get module error!");
		return FALSE;
	}
	LOG(addr_GetHash, "VM_GetHash Address", LSFN("%08X", addr_GetHash));
	ulong getHashOffset = Findfileoffset(module, addr_GetHash);
	LOG(getHashOffset, "VM_GetHash Offset", LSFN("%08X", getHashOffset));
	ulong wsize = 0;
	SetFilePointer(hFile, getHashOffset, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, "\xE9", 1, &wsize, NULL))
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		CloseHandle(hFile);
		LOGERROR("VMP get patch info error! write data failed error!");
		return FALSE;
	}
	ulong jmpvalue = module->base + module->size - addr_GetHash - 5 + __HashPatchEntry;
	if (!WriteFile(hFile, &jmpvalue, 4, &wsize, NULL))
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		CloseHandle(hFile);
		LOGERROR("VMP get patch info error! write data failed error!");
		return FALSE;
	}

	//set shellcode
	memcpy(outData, __VMPPatchHashShellCode, sizeof(__VMPPatchHashShellCode));

	//patch rdstc entry
	ulong addr_Rdtsc = (_handlersAddr[VM_Rdtsc] ? _handlersAddr[VM_Rdtsc]->addr : 0);
	if (addr_Rdtsc)
	{
		Inst_UD_Node* rdstccmd = _handlersAddr[VM_Rdtsc]->chain->GetHeader();
		while (rdstccmd)
		{
			if (rdstccmd->cmdInfo.optType == ASM_RDTSC)
			{
				break;
			}
			rdstccmd = rdstccmd->nextNode;
		}
		LOG(rdstccmd->cmdInfo.ip, "Rdstc Cmd Address", LSFN("%08X", rdstccmd->cmdInfo.ip));
		ulong rdtscOffset = Findfileoffset(module, rdstccmd->cmdInfo.ip);
		LOG(0, "Rdstc Cmd Offset", LSFN("%08X", rdtscOffset));
		SetFilePointer(hFile, rdtscOffset, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, "\xE9", 1, &wsize, NULL))
		{
			VirtualFree(outData, 0, MEM_RELEASE);
			CloseHandle(hFile);
			LOGERROR("VMP get patch info error! write data failed error!");
			return FALSE;
		}
		ulong jmpvalue = module->base + module->size - rdstccmd->cmdInfo.ip - 5 + __RdtscPatchEntry;
		if (!WriteFile(hFile, &jmpvalue, 4, &wsize, NULL))
		{
			VirtualFree(outData, 0, MEM_RELEASE);
			CloseHandle(hFile);
			LOGERROR("VMP get patch info error! write data failed error!");
			return FALSE;
		}
		//set rdtsc org cmd
		ulong rdtscorgcmdlen = 0;
		ulong newcmdlen = 0;
		rdstccmd = rdstccmd->nextNode;
		t_asmmodel asmmodel;
		char errtext[TEXTLEN];
		while (rdtscorgcmdlen < 5)
		{
			memset(&asmmodel, 0, sizeof(t_asmmodel));
			LOG(rdstccmd->cmdInfo.ip, "Rdtsc Org Cmd:", rdstccmd->cmdInfo.cmd);
			Assemble(rdstccmd->cmdInfo.cmd, module->base + module->size + __RdtscOrgCmd + rdtscorgcmdlen, &asmmodel, 0, 0, errtext);
			rdtscorgcmdlen += rdstccmd->cmdInfo.cmdLen;
			memcpy(outData + __RdtscOrgCmd + newcmdlen, asmmodel.code, asmmodel.length);
			newcmdlen += asmmodel.length;
			rdstccmd = rdstccmd->nextNode;
		}

		//set rdtsc return
		jmpvalue = rdstccmd->cmdInfo.ip - (module->base + module->size + __RdtscJmpRetn) - 5;
		memcpy(outData + __RdtscJmpRetn + 1, &jmpvalue, 4);

	}

	//patch check vmware
	ulong checkvmware = *(ULONG*)(outData + __CheckVMOffset);
	if (checkvmware)
	{
		LOG(checkvmware, "Check Vmware", LSFN("%08X", checkvmware));
		ulong checkvmwareOffset = Findfileoffset(module, checkvmware);
		LOG(0, "Check Vmware Offset", LSFN("%08X", checkvmwareOffset));
		SetFilePointer(hFile, checkvmwareOffset, NULL, FILE_BEGIN);
		if (!WriteFile(hFile, "\xCC", 1, &wsize, NULL))//replace by int3(0xCC)
		{
			VirtualFree(outData, 0, MEM_RELEASE);
			CloseHandle(hFile);
			LOGERROR("VMP get patch info error! write data failed error!");
			return FALSE;
		}
	}


	CloseHandle(hFile);
	LOG(0, NULL);
	while (hashinfos[i].vm_eip)
	{
		LOG(hashinfos[i].vm_eip, "Hash_EIP", LSFN("%08X", hashinfos[i].vm_eip));
		hashinfos[i].vm_eip = hashinfos[i].vm_eip - module->base;
		LOG(0, "Hash_Value", LSFN("%08X", hashinfos[i].hash_value));
		LOG(hashinfos[i].tableBase, "Hash_Table_Base", LSFN("%08X", hashinfos[i].tableBase));
		hashinfos[i].tableBase = hashinfos[i].tableBase - module->base;
		LOG(0, "Hash_Table_Size", LSFN("%08X", hashinfos[i].tableSize));
		LOG(0, "Hash_Table_Value", LSFN("%08X", hashinfos[i].tableValue));
		i++;
	}
	LOG(0, NULL);

	//set hash return
	jmpvalue = _dispatchInfo.opcodeLoadIP - (module->base + module->size + __HashJmpRetn) - 5;
	memcpy(outData + __HashJmpRetn + 1, &jmpvalue, 4);
	//set ReadDs32 return 
	ulong addr_ReadDs32 = (_handlersAddr[VM_ReadDs32] ? _handlersAddr[VM_ReadDs32]->addr : 0);
	jmpvalue = _dispatchInfo.opcodeLoadIP - (module->base + module->size + __ReadDs32JmpRetn) - 5;
	memcpy(outData + __ReadDs32JmpRetn + 1, &jmpvalue, 4);
	//set ReadDs32 data
	jmpvalue = (module->base + module->size + __ReadDs32PatchEntry) - addr_ReadDs32 - 5;
	memcpy(outData + __ReadDs32Data, &jmpvalue, 4);
	//set ReadDs32 orgdata
	ulong ReadDs32Orgdata = _POI(addr_ReadDs32);
	memcpy(outData + __ReadDs32OrgData1, &ReadDs32Orgdata, 4);
	ReadDs32Orgdata = _POI(addr_ReadDs32 + 4);
	memcpy(outData + __ReadDs32OrgData2, &ReadDs32Orgdata, 4);
	//set ReadDs32 offset
	addr_ReadDs32 -= module->base;
	memcpy(outData + __ReadDs32Offset, &addr_ReadDs32, 4);
	//set reloc
	memcpy(outData + __Reloc, &module->size, 4);
	//set esp change
	ulong espchange = *(ULONG*)(outData + __EspChangeDataOffset);
	LOG(0, "Esp Change", LSFN("%08X", espchange));
	memcpy(outData + __HashEspChange, &espchange, 4);
	//set Rdtsc eax
	ulong RdtscEax = *(ULONG*)(outData + __RdtscEaxOffset);
	LOG(0, "Rdtsc eax", LSFN("%08X", RdtscEax));
	memcpy(outData + __RdtscEax, &RdtscEax, 4);
	//set Rdtsc ebx
	ulong RdtscEdx = *(ULONG*)(outData + __RdtscEdxOffset);
	LOG(0, "Rdtsc edx", LSFN("%08X", RdtscEdx));
	memcpy(outData + __RdtscEdx, &RdtscEdx, 4);

	if (!PE_Add_Section(newFileName, outData, VMP_PATCH_HASH_DATA_SIZE, "OWO_Hash"))
	{
		VirtualFree(outData, 0, MEM_RELEASE);
		LOGERROR("VMP get patch info error! add section failed!");
		return false;
	}

	LOG(0, "Out File:", newFileName);

// 	strcat(newFileName, ".dmp");
// 	hFile = CreateFileA(newFileName, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
// 	if (hFile == INVALID_HANDLE_VALUE)
// 	{
// 		VirtualFree(outData, 0, MEM_RELEASE);
// 		LOGERROR("VMP get patch info error! create dmp file failed!");
// 		return false;
// 	}
// 	if (!WriteFile(hFile, outData, VMP_PATCH_HASH_DATA_SIZE, &wsize, NULL))
// 	{
// 		VirtualFree(outData, 0, MEM_RELEASE);
// 		CloseHandle(hFile);
// 		LOGERROR("VMP get patch info error! write data failed error1!");
// 		return FALSE;
// 	}
// 	CloseHandle(hFile);

	LOGTITLEEND;
	VirtualFree(outData, 0, MEM_RELEASE);
	HANDLE hProcess = (HANDLE)Plugingetvalue(VAL_HPROCESS);
	VirtualFreeEx(hProcess, (LPVOID)_patchHashDataAddr, 0, MEM_RELEASE);
	return true;
}

/*
esppos		espref
4			-4			x;jmp[]
0			-8			jmp[];x
0			-4			x;call[]
-4			-8			call[];x
4			0			x;mov[]
0			-4			mov[];x
*/
#define WORD_COMB(a,b) (a<<16|(b&0x0000FFFF))

BOOL VmpExplore::VmpFixApiUnit(ulong addr, t_module* module, HANDLE logfile)
{
	Inst_UD_Chain* chain = ReadCmdChain(addr, false, MAX_VMP_FIX_API_CMD_COUNT,false);
	if (!chain)
	{
		return -1;
	}
	//chain->PrintChain(true,true);


	ulong apiDecodeReg = 0;
	ulong apiDecodeMemAddr = 0;
	ulong apiDecodeMemOffset = 0;
	ulong apiDecodeIncrement = 0;
	ulong apiSetReg = 0;
	ulong apiAddr = 0;
	Inst_UD_Node* tmp = chain->GetHeader();
	while (tmp)
	{

		if (!apiDecodeReg)
		{
			if (tmp->cmdInfo.optType == ASM_MOV && (tmp->cmdInfo.op[1].opType&OP_IMM)
				&& tmp->cmdInfo.op[1].opConst>module->base && tmp->cmdInfo.op[1].opConst<module->base+module->size)
			{
				apiDecodeReg = tmp->cmdInfo.op[0].reg;
				apiDecodeMemAddr = tmp->cmdInfo.op[1].opConst;
				tmp = tmp->nextNode;
				continue;
			}
		}
		else if (!apiDecodeMemOffset)
		{
			if (tmp->cmdInfo.optType == ASM_MOV && tmp->cmdInfo.op[0].reg == apiDecodeReg)
			{
				apiDecodeMemOffset = tmp->cmdInfo.op[1].opConst;
				tmp = tmp->nextNode;
				continue;
			}
		}
		else if (!apiDecodeIncrement)
		{
			if (tmp->cmdInfo.optType == ASM_LEA && tmp->cmdInfo.op[0].reg == apiDecodeReg)
			{
				apiDecodeIncrement = tmp->cmdInfo.op[1].opConst;
				tmp = tmp->nextNode;
				continue;
			}
		}
		else
		{
			if (tmp->cmdInfo.op[1].reg == apiDecodeReg && (tmp->cmdInfo.op[1].opType&OP_REG))
			{
				if (tmp->cmdInfo.op[0].opType&tmp->cmdInfo.op[1].opType&OP_REG)
				{
					apiSetReg = tmp->cmdInfo.op[0].reg;
				}
				break;
			}
		}

		tmp = tmp->nextNode;
	}
	if (!tmp&&!apiSetReg)
	{
		apiSetReg = apiDecodeReg;
	}
	//LOG(0, "ApiDecodeReg:", ASM_REG_KEY[RegType2RegIndex(apiDecodeReg)]);
	//LOG(0, "ApiDecodeMemAddr:", LSFN("%08X", apiDecodeMemAddr));
	//LOG(0, "ApiDecodeMemOffset:", LSFN("%08X", apiDecodeMemOffset));
	//LOG(0, "ApiDecodeIncrement:", LSFN("%08X", apiDecodeIncrement));
// 	if (apiSetReg)
// 	{
// 		LOG(0, "apiSetReg:", ASM_REG_KEY[RegType2RegIndex(apiSetReg)]);
// 	}
	char ApiName[TEXTLEN];
	t_module* ApiModule;
	if (apiDecodeMemAddr!=0 && apiDecodeMemOffset!=0 && apiDecodeIncrement!=0)
	{
		apiAddr = _POI(apiDecodeMemAddr + apiDecodeMemOffset) + apiDecodeIncrement;
		ApiModule = Findmodule(apiAddr);
		ApiName[0] = 0;
		Findname(apiAddr, NM_EXPORT, ApiName);
		if (!ApiName[0] || !ApiModule)
		{
			delete chain;
			//LOG2FILE(logfile, "ERROR: API module or name not found! CallAddr:%08X, ApiAddr:%08X", addr, apiAddr);
			LOG2FILE(logfile, "ERROR: API module or name not found! CallAddr:%08X  ApiAddr:%08X  ApiDecodeReg:%s  ApiDecodeMemAddr:%08X"
				"  ApiDecodeMemOffset:%08X  ApiDecodeIncrement:%08X"
				, addr, apiAddr, ASM_REG_KEY[RegType2RegIndex(apiDecodeReg)], apiDecodeMemAddr, apiDecodeMemOffset, apiDecodeIncrement);
			LOG(addr, "ERROR: API module or name not found!", LSFN("CallAddr:%08X  ApiAddr:%08X  ApiDecodeReg:%s  ApiDecodeMemAddr:%08X"
				"  ApiDecodeMemOffset:%08X  ApiDecodeIncrement:%08X", addr, apiAddr, ASM_REG_KEY[RegType2RegIndex(apiDecodeReg)], apiDecodeMemAddr, apiDecodeMemOffset, apiDecodeIncrement));
			return false;
		}
	}
	else
	{
		delete chain;
		LOG2FILE(logfile, "WARNING: Cann't parse API decode chain. CallAddr:%08X", addr);
		return -1;
	}
	int retespref = chain->GetTail()->preNode->espPosRef;
	int esppos = (WORD)chain->GetEspPos();
	bool ret = TRUE;
	ULONG jmpValue = 0;
	uchar regindex;
	uchar opvalue = 0xB8;
	switch (WORD_COMB(esppos, retespref))
	{
	case WORD_COMB(4, -4):
		LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(x;jmp[])\tFixAddr:%08X, FixCmd:JMP [&%-0.8s.%s]",
			addr, apiAddr, addr-1, ApiModule->name, ApiName);

		jmpValue = apiAddr - (addr-1) - 5;
		Writememory("\xE9", addr - 1, 1, MM_RESILENT);
		Writememory(&jmpValue, addr, 4, MM_RESILENT);
		Writememory("\x90", addr + 4, 1, MM_RESILENT);
		break;
	case WORD_COMB(0, -8):
		LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(jmp[];x)\tFixAddr:%08X  FixCmd:JMP [&%-0.8s.%s]",
			addr, apiAddr, addr, ApiModule->name, ApiName);
		jmpValue = apiAddr - addr - 5;
		Writememory("\xE9", addr, 1, MM_RESILENT);
		Writememory(&jmpValue, addr+1, 4, MM_RESILENT);
		Writememory("\x90", addr + 5, 1, MM_RESILENT);
		break;
	case WORD_COMB(0, -4):
		if (apiSetReg)
		{
			regindex = (uchar)RegType2RegIndex(apiSetReg);
			LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(mov[];x)\tFixAddr:%08X  FixCmd:MOV %s,[&%-0.8s.%s]",
				addr, apiAddr, addr, ASM_REG_KEY[regindex], ApiModule->name, ApiName);
			opvalue = 0xB8 + regindex;
			Writememory(&opvalue, addr, 1, MM_RESILENT);
			Writememory(&apiAddr, addr+1, 4, MM_RESILENT);
			Writememory("\x90", addr + 5, 1, MM_RESILENT);
		}
		else
		{
			LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(x;call[])\tFixAddr:%08X  FixCmd:Call [&%-0.8s.%s]",
				addr, apiAddr, addr - 1, ApiModule->name, ApiName);
			jmpValue = apiAddr - (addr - 1) - 5;
			Writememory("\xE8", addr - 1, 1, MM_RESILENT);
			Writememory(&jmpValue, addr, 4, MM_RESILENT);
			Writememory("\x90", addr + 4, 1, MM_RESILENT);
		}
		break;
	case WORD_COMB(-4, -8):
		if (apiSetReg)
		{
			regindex = (uchar)RegType2RegIndex(apiSetReg);
			LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(pop;mov[])\tFixAddr:%08X  FixCmd:MOV %s,[&%-0.8s.%s]",
				addr, apiAddr, addr - 1, ASM_REG_KEY[regindex], ApiModule->name, ApiName);
			opvalue = 0xB8 + regindex;
			Writememory(&opvalue, addr - 1, 1, MM_RESILENT);
			Writememory(&apiAddr, addr, 4, MM_RESILENT);
			Writememory("\x90", addr + 4, 1, MM_RESILENT);
		}
		else
		{
			LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(call[];x)\tFixAddr:%08X  FixCmd:CALL [&%-0.8s.%s]",
				addr, apiAddr, addr, ApiModule->name, ApiName);
			jmpValue = apiAddr - addr - 5;
			Writememory("\xE8", addr, 1, MM_RESILENT);
			Writememory(&jmpValue, addr + 1, 4, MM_RESILENT);
			Writememory("\x90", addr + 5, 1, MM_RESILENT);
		}

		break;
	case WORD_COMB(4, 0):
		regindex = (uchar)RegType2RegIndex(apiSetReg);
		LOG2FILE(logfile, "CallAddr:%08X  ApiAddr:%08X  ApiMode:(push;mov[])\tFixAddr:%08X  FixCmd:MOV %s,[&%-0.8s.%s]",
			addr, apiAddr, addr - 1, ASM_REG_KEY[regindex], ApiModule->name, ApiName);
		opvalue = 0xB8 + regindex;
		Writememory(&opvalue, addr -1, 1, MM_RESILENT);
		Writememory(&apiAddr, addr, 4, MM_RESILENT);
		Writememory("\x90", addr + 4, 1, MM_RESILENT);
		break;
	default:
		ret = FALSE;
		char* logformat = "ERROR: ApiMode not found! CallAddr:%08X  ApiAddr:%08X  ApiDecodeReg:%s  ApiDecodeMemAddr:%08X"
			"  ApiDecodeMemOffset:%08X  ApiDecodeIncrement:%08X  EspPos:%d  EspRef:%d";
		LOG2FILE(logfile, logformat, addr, apiAddr, ASM_REG_KEY[RegType2RegIndex(apiDecodeReg)], apiDecodeMemAddr, apiDecodeMemOffset, apiDecodeIncrement,esppos, retespref);
		//LOG(addr, "ERROR: ApiMode not found! ", LSFN("CallAddr: % 08X  ApiAddr : % 08X  ApiDecodeReg : %s  ApiDecodeMemAddr : % 08X"
		//	"  ApiDecodeMemOffset:%08X  ApiDecodeIncrement:%08X  EspPos:%d  EspRef:%d", addr, apiAddr, ASM_REG_KEY[RegType2RegIndex(apiDecodeReg)], apiDecodeMemAddr, apiDecodeMemOffset, apiDecodeIncrement, esppos, retespref));
		break;
	}
	delete chain;
	return ret;
}


bool VmpExplore::VmpFixApi(ulong addr)
{
	t_memory* mem = Findmemory(addr);
	t_module* module = Findmodule(addr);
	if (!mem || !module)
	{
		LOGERROR("VMP_fix_api get seg mem info error!");
		return false;
	}
	LOGTITLE("VMP Fix Api:");
	char* filename = (char*)Plugingetvalue(VAL_EXEFILENAME);
	char LogFileName[MAX_PATH];
	strcpy_s(LogFileName, filename);
	strcat_s(LogFileName, LSFI("_FixApi_%08X-%08X.txt",mem->base,mem->base+mem->size));
	LOG(0, "Log File:", LogFileName);
	HANDLE logfile = CREATE_LOGFILE(LogFileName);
	if (!logfile)
	{
		LOGERROR("VMP_fix_api create log file error!");
		LOGTITLEEND;
		return false;
	}

	ulong searchsize = 0;
	char* findbuf = (char*)VirtualAlloc(NULL, VMP_PATCH_HASH_DATA_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!findbuf)
	{
		LOGERROR("VMP_fix_api alloc find buf error!");
		CLOSE_LOGFILE(logfile);
		LOGTITLEEND;
		return false;
	}
	ulong successCount = 0;
	ulong failedCount = 0;
	while (searchsize<mem->size)
	{
		if (Readmemory(findbuf, mem->base + searchsize, VMP_PATCH_HASH_DATA_SIZE, MM_RESILENT) != VMP_PATCH_HASH_DATA_SIZE)
		{
			VirtualFree(findbuf, 0, MEM_RELEASE);
			LOGERROR("VMP_fix_api alloc read find buf error!");
			CLOSE_LOGFILE(logfile);
			LOGTITLEEND;
			return false;
		}
		char* findsel = findbuf;
		char* findchr = NULL;
		while (1)
		{
			findchr = (char*)memchr(findsel, 0xE8, VMP_PATCH_HASH_DATA_SIZE - (findsel - findbuf));
			if (!findchr)
			{
				break;
			}
			ulong callAddr = findchr - findbuf + mem->base + searchsize;
			ulong callValue = _POI(callAddr+1);
			if (callValue)
			{
				ulong callToAddr = callValue + callAddr + 5;
				if (callToAddr>module->base && callToAddr<module->base+module->size)
				{
					BOOL result = VmpFixApiUnit(callAddr, module, logfile);
					if (result == TRUE)
					{
						successCount++;
					}
					else if (result == FALSE)
					{
						failedCount++;
					}
				}
			}
			
			findsel = findchr + 1;
		}
		searchsize += VMP_PATCH_HASH_DATA_SIZE;
	}
	LOG2FILE(logfile, "Success Fix Count: %d", successCount);
	//LOG2FILE(logfile, "Failed Fix Count: %d", failedCount);
	LOG(0, "Success Fix Count:", LSFN("%d", successCount));
	//LOG(0, "Failed Fix Count:", LSFN("%d", failedCount));
	Analysecode(module);
	VirtualFree(findbuf, 0, MEM_RELEASE);
	CLOSE_LOGFILE(logfile);
	LOGTITLEEND;
	return true;
}

bool VmpExplore::VmpToOEPWithPathAntiDump()
{
	ulong addr_Retn = (_handlersAddr[VM_Retn] ? _handlersAddr[VM_Retn]->addr : 0);
	if (!addr_Retn)
	{
		LOGERROR("VMP patch hash get VM_Retn address error!");
		return false;
	}
	ulong modulebase = Plugingetvalue(VAL_MAINBASE);
	addr_Retn -= modulebase;
	ulong addr_EP = Findmodule(modulebase)->entry - modulebase;

	HMODULE hModule = GetModuleHandle("OoWoodOne.dll");
	HRSRC hRsrc = FindResource(hModule, MAKEINTRESOURCE(IDR_VMP_TO_OEP_WITH_PATCH_ANTIDUMP), TEXT("OSC"));
	if (NULL == hRsrc)
	{
		LOGERROR("VMP to OEP error! osc Resource not find!");
		return false;
	}
	DWORD dwSize = SizeofResource(hModule, hRsrc);
	if (0 == dwSize)
	{
		return false;
	}
	HGLOBAL hGlobal = LoadResource(hModule, hRsrc);
	if (NULL == hGlobal)
	{
		return false;
	}
	LPVOID pBuffer = LockResource(hGlobal);
	if (NULL == pBuffer)
	{
		return false;
	}
	char* curdir = (char*)Plugingetvalue(VAL_CURRENTDIR);
	if (!curdir)
	{
		return false;
	}
	char path[MAX_PATH];
	GetTempPath(MAX_PATH, path);
	strcat_s(path, "/VMP_To_OEP_With_Patch_AntiDump.osc");
	HANDLE hFile = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_WRITE, NULL
		, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
	{
		return false;
	}
	ulong wsize = 0;
	if (!WriteFile(hFile, pBuffer, dwSize, &wsize, NULL))
	{
		CloseHandle(hFile);
		return false;
	}
	char* inputstr = LSFI("\r\nMOV VM_Retn,%08X\r\nMOV EntryPoint,%08X\r\nRET", addr_Retn,addr_EP);
	if (!WriteFile(hFile, inputstr, strlen(inputstr), &wsize, NULL))
	{
		CloseHandle(hFile);
		return false;
	}
	CloseHandle(hFile);

	HMODULE hMod = GetModuleHandle("ODbgScript.dll");
	if (hMod) // 检测是否被其他插件加载
	{
		int(*pFunc)(char*) = (int(*)(char*)) GetProcAddress(hMod, "ExecuteScript");
		if (pFunc) // 检查是否获得输出函数
		{
			pFunc(path); // 执行输出函数
		}
		else
		{
			LOGERROR("VMP to OEP error! ODbgScript.dll&ExecuteScript not found!");
			return false;
		}
	}
	else
	{
		LOGERROR("VMP to OEP error! module ODbgScript.dll not found!");
		return false;
	}
	DeleteFile(path);
	return true;
}


bool VmpExplore::VmpAnalyseCode(ulong vmEip, ulong joinRegValue, int vmEspStart)
{
	LOG(0, LSFI("VMP Analyse Code Start:%08X", vmEip), NULL, LOG_TITLE_INDENT);

	char* filename = (char*)Plugingetvalue(VAL_EXEFILENAME);
	char LogFileName[MAX_PATH];
	strcpy_s(LogFileName, filename);
	strcat_s(LogFileName, LSFI("_VM_Code_%08X.txt", vmEip));
	LOG(0, "Log File:", LogFileName);
	LOG(0, "");

	HANDLE logfile = CREATE_LOGFILE(LogFileName);
	LOG2FILE(logfile, "VM_EIP\t\tVM_ESP\tHandler\t\t\t\tValue");
	ulong NowEsi = vmEip;
	ulong NowJRV = joinRegValue;
	int NowVmEsp = vmEspStart;
	code_handle* chLoadOpcode = CreateCodeHandle2(_dispatchInfo.opcodeDecode.header->nextCmd->nextCmd,_dispatchInfo.opcodeDecodeReg,_dispatchInfo.opcodeJoinReg);
	if (!chLoadOpcode)
	{
		LOGERROR("VMP Analyse Code, Create Code Handle error!");
		LOGTITLEEND;
		CLOSE_LOGFILE(logfile);
		return false;
	}
	while (1)
	{
		ulong opd = (uchar)_POI(NowEsi + _dispatchInfo.esiOffset);
		DoCodeHandle2(chLoadOpcode, opd, NowJRV, &opd, &NowJRV);
		NowEsi += _dispatchInfo.esiChange;

		vmp_handler_addr* vha = _handlersAddr[_handlers[opd].handler];

		while (vha)
		{
			if (vha->addr == _handlers[opd].addr)
				break;
			vha = vha->next;
		}

		if (!vha)
		{
			LOGERROR("VMP Analyse Code, Handle not found!");
			FreeCodeHandle(chLoadOpcode);
			LOGTITLEEND;
			CLOSE_LOGFILE(logfile);
			return false;
		}
		NowVmEsp += vha->ebpChange;
		if (!vha->esiChange)
		{
			
			if (_handlers[opd].handler == VM_PopR32 || _handlers[opd].handler == VM_PushR32)
			{
				code_handle* chLoadData = CreateCodeHandle2(vha->dataDecode.header, _dispatchInfo.opcodeDecodeReg, _dispatchInfo.opcodeJoinReg);
				if (!chLoadData)
				{
					FreeCodeHandle(chLoadOpcode);
					LOGERROR("VMP Analyse Code, Create Code Handle error!");
					LOGTITLEEND;
					CLOSE_LOGFILE(logfile);
					return false;
				}
				ulong opd0 = opd;
				DoCodeHandle2(chLoadData, opd0, NowJRV, &opd0, &NowJRV);
				LOG(NowEsi, LSFI("%4d    %s", NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler)), LSFN("R%d", opd0 / 4));
				LOG2FILE(logfile, "%08X\t%4d\t%s\t\t\tR%d", NowEsi, NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler), opd0 / 4);
				FreeCodeHandle(chLoadData);
			}
			else if (_handlers[opd].handler == VM_PopEsp)
			{
				LOG(NowEsi, LSFI("  ??    %s", VmpHandler::GetHandler((vm_handler)_handlers[opd].handler)));
				LOG2FILE(logfile, "%08X\t  ??\t%s", NowEsi, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler));
			}
			else 
			{
				LOG(NowEsi, LSFI("%4d    %s", NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler)));
				LOG2FILE(logfile, "%08X\t%4d\t%s", NowEsi, NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler));
				if (_handlers[opd].handler == VM_Jmp || _handlers[opd].handler == VM_Retn)
					break;
			}
			
		}
		else
		{
			code_handle* chLoadData = CreateCodeHandle2(vha->dataDecode.header, _dispatchInfo.opcodeDecodeReg, _dispatchInfo.opcodeJoinReg);
			if (!chLoadData)
			{
				FreeCodeHandle(chLoadOpcode);
				LOGERROR("VMP Analyse Code, Create Code Handle error!");
				LOGTITLEEND;
				CLOSE_LOGFILE(logfile);
				return false;
			}

			ulong shiftv = (32 - (vha->esiOffsetDigit >> 16) * 8);
			ulong opd0 = _POI(NowEsi + vha->esiOffset) << shiftv >> shiftv;
			DoCodeHandle2(chLoadData, opd0, NowJRV, &opd0, &NowJRV);

			switch (_handlers[opd].handler)
			{
			case VM_PopR16:
			case VM_PopR32:
			case VM_PopR8:
			case VM_PushR16:
			case VM_PushR32:
				LOG(NowEsi, LSFI("%4d    %s", NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler)), LSFN("R%d", opd0 / 4));
				LOG2FILE(logfile, "%08X\t%4d\t%s\t\t\tR%d", NowEsi, NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler), opd0 / 4);
				break;
			default:
				LOG(NowEsi, LSFI("%4d    %s", NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler)), LSFN("%X", opd0));
				LOG2FILE(logfile, "%08X\t%4d\t%s\t\t\t%X", NowEsi, NowVmEsp, VmpHandler::GetHandler((vm_handler)_handlers[opd].handler), opd0);
				break;
			}
			

			NowEsi += vha->esiChange;
			FreeCodeHandle(chLoadData);
		}
	}



	FreeCodeHandle(chLoadOpcode);
	CLOSE_LOGFILE(logfile);
	LOGTITLEEND;
	return true;
}


bool VmpExplore::IsVMHandler(ulong addr, vm_handler vh)
{
	vmp_handler_addr* tmp = _handlersAddr[vh];
	while (tmp)
	{
		if (tmp->addr == addr)
		{
			return true;
		}
		tmp = tmp->next;
	}
	return false;
}