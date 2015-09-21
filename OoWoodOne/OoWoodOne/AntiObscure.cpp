#include <Windows.h>
#include "Plugin.h"
#include "LogWindow.h"
#include "AntiObscure.h"
#include "AsmForm.h"

Inst_UD_Chain::Inst_UD_Chain():
_header(NULL),
_tail(NULL),
_esp_pos(NULL)
{

}

Inst_UD_Chain::~Inst_UD_Chain()
{
	ClearChain();
}

//add node with analyse ud automatically.
bool Inst_UD_Chain::AddNode(t_disasm* disasm, void* cmdBuf, ulong cmdLen, bool optimize )
{
	Inst_UD_Node* node = AnalyseUD(disasm, cmdBuf, cmdLen);
	return AddNode(node, optimize);
}

//add node.
bool Inst_UD_Chain::AddNode(Inst_UD_Node* node, bool optimize)
{

	if (!node)
		return false;

	if (_tail == NULL)//empty
	{
		_header = node;
		_tail = node;
	}
	else
	{
		_tail->nextNode = node;
		node->preNode = _tail;
		_tail = node;
	}
	_esp_pos += node->stackDef;
	node->espPos = _esp_pos;
	//Addtolist(node->ip, 0, "Cmd: %s,      Def:[%08X], Ref:[%08X], Sk:[%d], Esp:[%d] ,EspDef:[%d]", node->cmd, node->opDef, node->opRef, node->stackDef, _esp_pos,node->espPosDef);
	//OptimizeUD();
	if (optimize)
	{
		OptimizeStack();
		OptimizeUD(_tail);
	}
	return true;
}


void Inst_UD_Chain::OptimizeStack()
{
	if (!_tail)
		return;
	if ( _tail->stackDef <= 0 )
		return;
	Inst_UD_Node* tmp = _tail;
	if (_tail->cmdInfo.optType == ASM_POP)
	{
		while (tmp->preNode)
		{
			if (!tmp->preNode->isDiscarded )
			{
				if (tmp->preNode->stackDef<0 && tmp->preNode->espPos < _esp_pos)
				{
					tmp->preNode->stackDef = 0;
					_tail->stackDef = 0;
					tmp->preNode->isDiscarded = true;
					//Addtolist(tmp->preNode->ip, 0, "    del  %s ,[Esp: %d]", tmp->preNode->cmd, tmp->preNode->espPos);
					//DeleteNode(tmp->preNode);
					break;
				}
				else if (tmp->preNode->stackDef && tmp->preNode->espPosDef < _esp_pos)
				{
					//Addtolist(tmp->preNode->ip, 0, "    del  %s ,[Esp: %d]", tmp->preNode->cmd, tmp->preNode->espPos);
					//DeleteNode(tmp->preNode);
					tmp->preNode->isDiscarded = true;
					continue;
				}
				else if (tmp->preNode->espPos >= _esp_pos)
				{
					break;
				}
			}

			tmp = tmp->preNode;
		}
	}
	else if (_tail->cmdInfo.optType == ASM_RETN)
	{
		bool haveOneChange = true;
		while (tmp->preNode)
		{
			if (!tmp->preNode->isDiscarded)
			{
				if (tmp->preNode->stackDef<0 && tmp->preNode->espPos < _esp_pos)
				{
					if (!haveOneChange)
					{
						//Addtolist(tmp->preNode->ip, 0, "    del  %s ,[Esp: %d]", tmp->cmd, tmp->preNode->espPos);
						//DeleteNode(tmp->preNode);
						tmp->preNode->isDiscarded = true;
					}
					else
					{
						tmp = tmp->preNode;
						haveOneChange = false;
					}
					continue;
				}
				else if (tmp->preNode->stackDef && tmp->preNode->espPosDef<_esp_pos)
				{
					//Addtolist(tmp->preNode->ip, 0, "    del  %s ,[Esp: %d]", tmp->cmd, tmp->preNode->espPos);
					//DeleteNode(tmp->preNode);
					tmp->preNode->isDiscarded = true;
					continue;
				}
				else if (tmp->preNode->espPos >= _esp_pos)
				{
					break;
				}
			}

			tmp = tmp->preNode;
		}
	}
	else
	{
		while (tmp->preNode)
		{
			if (!tmp->preNode->isDiscarded)
			{
				if (tmp->preNode->stackDef<0 && tmp->preNode->espPos < _esp_pos)
				{
					//Addtolist(tmp->preNode->cmdInfo.ip, 0, "    del  %s ,[Esp: %d]", tmp->cmdInfo.cmd, tmp->preNode->espPos);
					//DeleteNode(tmp->preNode);
					tmp->preNode->isDiscarded = true;
					continue;
				}
				else if (tmp->preNode->stackDef && tmp->preNode->espPosDef<_esp_pos)
				{
					//Addtolist(tmp->preNode->cmdInfo.ip, 0, "    del  %s ,[Esp: %d]", tmp->cmdInfo.cmd, tmp->preNode->espPos);
					//DeleteNode(tmp->preNode);
					tmp->preNode->isDiscarded = true;
					continue;
				}
				else if (tmp->preNode->espPos>=_esp_pos)
				{
					//Addtolist(_tail->cmdInfo.ip, 0, "    del  %s ,[Esp: %d]", _tail->cmdInfo.cmd, _tail->espPos);
					//DeleteNode(_tail);
					_tail->isDiscarded = true;
					break;
				}
			}

			tmp = tmp->preNode;
		}
	}

}

//optimize the ud chain.
void Inst_UD_Chain::OptimizeUD(Inst_UD_Node* node)
{
	if (!node)
		return;
	ulong unselfDef = (node->opRef & node->opDef) ^ node->opDef;
	//def self or no def  
	if (!unselfDef)
		return;
	Inst_UD_Node* tmp = node;
	//Addtolist(tmp->ip, 0, "    %s", tmp->result);
	while (tmp->preNode)
	{
		if (!tmp->preNode->isDiscarded)
		{
			if (!tmp->preNode->espPosDef && !tmp->preNode->ebpPosDef)
			{
				tmp->preNode->opDef ^= (tmp->preNode->opDef & unselfDef);
				if (!(tmp->preNode->opDef + tmp->preNode->stackDef))
				{
					//Addtolist(tmp->preNode->ip, 0, "    del  %s", tmp->cmd);
					//DeleteNode(tmp->preNode);
					tmp->preNode->isDiscarded = true;
					continue;
				}

			}
			if (tmp->preNode->opRef&unselfDef)
			{
				break;
			}
		}

		tmp = tmp->preNode;
	}
	//if (tmp->preNode)
	//	Addtolist(tmp->preNode->ip, 0, "    arv  %s", tmp->cmd);
	//else
	//	Addtolist(0, 0, "    arv  header");
}

void Inst_UD_Chain::OptimizeChain()
{
	if (!_tail)
		return;
	Inst_UD_Node* tmp = _tail;
	while (tmp)
	{
		if (!tmp->isDiscarded)
		{
			if (tmp->espPosDef | tmp->espPosRef | tmp->opDef | tmp->opRef)
			{
				OptimizeUD(tmp);
			
			}
			else
			{
				tmp->isDiscarded = true;
			}
		}
		tmp = tmp->preNode;
	}
}
//delete node.
bool Inst_UD_Chain::DeleteNode(Inst_UD_Node* node)
{
	if (!node)
		return false;

	if (node == _header)
	{
		_header = node->nextNode;
	}
	if (node == _tail)
	{
		_tail = node->preNode;
	}
	if (node->preNode)
	{
		node->preNode->nextNode = node->nextNode;
	}
	if (node->nextNode)
	{
		node->nextNode->preNode = node->preNode;
	}
	delete node;
	return true;
}

//clear chain.
void Inst_UD_Chain::ClearChain()
{
	while (_header)
	{
		DeleteNode(_header);
	}
}

Inst_UD_Node* Inst_UD_Chain::FindNode(ulong ip)
{
	Inst_UD_Node* tmp=_header;
	while (tmp)
	{
		if (tmp->cmdInfo.ip == ip)
		{
			return tmp;
		}
		tmp = tmp->nextNode;
	}
	return false;
	
}

//print instructions.
void Inst_UD_Chain::PrintChain(bool showDiscard, bool showArg)
{
	LOGTITLE(LSFI("Print Chain: %08X %s", _header->cmdInfo.ip,(showDiscard ? "Unoptimize":"Optimize")));
	Inst_UD_Node* tmp = _header;
	char* name = new char[TEXTLEN];
	if (showDiscard)
	{
		while (tmp)
		{
			int isfindname = Findname(tmp->cmdInfo.ip, NM_COMMENT, name);
			LOG(tmp->cmdInfo.ip, tmp->cmdInfo.cmd, showArg ?
				LSFN("Def:[%08X], Ref:[%08X], Sk:[%d], EspDef:[%d], EspRef:[%d], EspRRef:[%d]", tmp->opDef, tmp->opRef, tmp->stackDef, tmp->espPosDef, tmp->espPosRef, tmp->espPosRRef):(isfindname ? name : NULL));
				//);
			tmp = tmp->nextNode;
		}
	}
	else
	{
		while (tmp)
		{
			if (!tmp->isDiscarded)
			{
				int isfindname = Findname(tmp->cmdInfo.ip, NM_COMMENT, name);
				LOG(tmp->cmdInfo.ip, tmp->cmdInfo.cmd, showArg ?
					LSFN("Def:[%08X], Ref:[%08X], Sk:[%d], EspDef:[%d], EspRef:[%d], EspRRef:[%d]", tmp->opDef, tmp->opRef, tmp->stackDef, tmp->espPosDef, tmp->espPosRef, tmp->espPosRRef) : (isfindname ? name : NULL));
			}
				//LSFN("Def:[%08X], Ref:[%08X], Sk:[%d], EspDef:[%d], EspRef:[%d], EspRRef:[%d]", tmp->opDef, tmp->opRef, tmp->stackDef, tmp->espPosDef, tmp->espPosRef, tmp->espPosRRef));
			tmp = tmp->nextNode;
		}
	}
	LOG(0, "ESP Pos", LSFN("%d",_esp_pos));
	delete[] name;
	LOGTITLEEND;
}


//analyse ud, return node.
#define __addRef(x) node->opRef|=(x)
#define __addDef(x) node->opDef|=(x)
#define __addSkDef(x) node->stackDef=(x)
#define __addEspDef(x) node->espPosDef=(x)
#define __addEspRef(x) node->espPosRef=(x)
#define __addEbpDef(x) node->ebpPosDef=(x)
#define __addEbpRef(x) node->ebpPosRef=(x)
#define __isMemOp(x) (node->cmdInfo.op[x].opType & OP_MEM)


Inst_UD_Node* Inst_UD_Chain::AnalyseUD(t_disasm* disasm, void* cmdBuf, ulong cmdLen)
{
	if (!disasm)
	{
		return NULL;
	}

	Inst_UD_Node* node = new Inst_UD_Node;
	memset(node, 0, sizeof(Inst_UD_Node));
	convertDisasm2Cmdinfo(disasm, cmdBuf, cmdLen, &node->cmdInfo);
	

	//get reg .
	ulong udr[3];
	udr[0] = node->cmdInfo.op[0].reg;
	udr[1] = node->cmdInfo.op[1].reg;
	udr[2] = node->cmdInfo.op[2].reg;
	switch (node->cmdInfo.optType)
	{		
		case ASM_AND:
		case ASM_BSWAP:
		case ASM_OR:
		case ASM_XOR:
		case ASM_ROL:
		case ASM_ROR:
		case ASM_RCL:
		case ASM_RCR:
		case ASM_SAL:
		case ASM_SAR:
		case ASM_SHL:
		case ASM_SHR:
		case ASM_SHLD:
		case ASM_SHRD:
		case ASM_NEG:
		case ASM_NOT:
		case ASM_BTC:
		case ASM_BTR:
		case ASM_BTS:
		case ASM_BSF:
		{
			if (__isMemOp(0))
			{
				__addRef(udr[0]);
				if (udr[0] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			else
			{
				__addDef(udr[0]);
			}
			__addRef(udr[0]);
			__addRef(udr[1]);
			break;
		}
		case ASM_ADD:
		case ASM_ADC:
		{
			if (__isMemOp(0))
			{
				__addRef(udr[0]);
				if (udr[0] == ud_esp)
				{
					__addEspDef(_esp_pos + disasm->adrconst);
				}
				else if (udr[0] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			else
			{
				__addDef(udr[0]);
				if (udr[0] == ud_esp)
				{
					__addSkDef(disasm->immconst) ;
				}
			}
			if (__isMemOp(1))
			{
				if (udr[1] == ud_esp)
				{
					__addEspRef(_esp_pos + disasm->adrconst);
				}
				else if (udr[1] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			__addRef(udr[0]);
			__addRef(udr[1]);
			break;
		}
		case ASM_SUB:
		case ASM_SBB:
		{
			if (__isMemOp(0))
			{
				__addRef(udr[0]);
				if (udr[0] == ud_esp)
				{
					__addEspDef(_esp_pos + disasm->adrconst);
				}
				else if (udr[0] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			else
			{
				__addDef(udr[0]);
				if (udr[0] == ud_esp)
				{
					__addSkDef(-(int)disasm->immconst) ;
				}
			}
			if (__isMemOp(1))
			{
				if (udr[1] == ud_esp)
				{
					__addEspRef(_esp_pos + disasm->adrconst);
				}
				else if (udr[1] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			__addRef(udr[0]);
			__addRef(udr[1]);
			break;
		}
		case ASM_DEC:
		case ASM_INC:
		{
			__addRef(udr[0]);
			if (!__isMemOp(0))
			{
				__addDef(udr[0]);
			}
			break;
		}
		case ASM_CMP:
		case ASM_TEST:
		case ASM_BT:
		{
			__addRef(udr[0]);
			__addRef(udr[1]);
			break;
		}
		case ASM_LEA:
		{
			__addDef(udr[0]);
			__addRef(udr[1]);
			if (udr[0] == ud_esp && udr[1] == ud_esp)
			{
				__addSkDef(disasm->adrconst);
			}
			if (udr[1] == ud_esp)
			{
				node->espPosRRef = _esp_pos + disasm->adrconst;
			}
			break;
		}
		case ASM_CALL:
		{
			__addRef(udr[0]);
			__addSkDef(-4);
			__addEspDef(_esp_pos - 4);
			break;
		}
		case ASM_RET:
		case ASM_RETN:
		{
			__addRef(ud_esp);
			__addDef(ud_esp);
			__addSkDef(disasm->immconst+4);
			__addEspRef(_esp_pos + disasm->immconst);
			break;
		}
		case ASM_POP:
		{
			if (__isMemOp(0))
			{
				__addRef(udr[0]);
				if (udr[0] == ud_esp)
				{
					__addEspDef(_esp_pos + disasm->adrconst+4);
				}
			}
			else
			{
				__addDef(udr[0]);
			}
			__addRef(ud_esp);
			__addDef(ud_esp);
			__addSkDef(4);
			__addEspRef(_esp_pos);
			break;
		}
		case ASM_POPFD:
		{
			if (__isMemOp(0))
			{
				__addRef(udr[0]);
			}
			else
			{
				__addDef(udr[0]);
			}
			__addRef(ud_esp);
			__addDef(ud_esp);
			__addSkDef(4);
			__addEspRef(_esp_pos);
			break;
		}
		case ASM_PUSH:
		{
			if (__isMemOp(0) && udr[0] == ud_esp)
			{
				__addEspRef(_esp_pos + disasm->adrconst);
			}
			__addRef(udr[0]);
			__addRef(ud_esp);
			__addDef(ud_esp);
			__addSkDef(-4);
			__addEspDef(_esp_pos - 4);
			break;
		}
		case ASM_PUSHFD:
		{
			__addRef(udr[0]);
			__addRef(ud_esp);
			__addDef(ud_esp);
			__addSkDef(-4);
			__addEspDef(_esp_pos - 4);
			break;
		}
		case ASM_PUSHAD:
		{
			__addRef(ud_all);
			__addSkDef(-32);
			__addEspDef(_esp_pos - 32);
			break;
		}
		case ASM_POPAD:
		{
			__addDef(ud_all);
			__addSkDef(32);
			__addEspRef(_esp_pos);
			break;
		}
		case ASM_RDTSC:
		{
			__addDef(ud_eax);
			__addDef(ud_edx);
			break;
		}
		case ASM_CPUID:
		{
			__addRef(ud_eax);
			__addDef(ud_eax);
			__addDef(ud_ecx);
			break;
		}
		default:
		{
			if (__isMemOp(0))
			{
				__addRef(udr[0]);
				if (udr[0] == ud_esp)
				{
					__addEspDef(_esp_pos + disasm->adrconst);
				}
				else if (udr[0] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			else
			{
				__addDef(udr[0]);
			}
			if (__isMemOp(1))
			{
				if (udr[1] == ud_esp)
				{
					__addEspRef(_esp_pos + disasm->adrconst);
				}
				else if (udr[1] == ud_ebp)
				{
					__addEbpDef(1);
				}
			}
			else
			{
				if (udr[1] == ud_esp)
				{
					node->espPosRRef = _esp_pos + disasm->adrconst;
				}
			}
			__addRef(udr[1]);
			__addRef(udr[2]);
			break;
		}
	}

	return node;
}



