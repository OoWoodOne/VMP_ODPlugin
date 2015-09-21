#include <Windows.h>
#include "VmpHandler.h"

const char* VmpHandler::_vmh[] =
{
	"VM_Unknown",
	"Invalid handler",
	"VM_Add16",
	"VM_Add32",
	"VM_Add8",
	"VM_CallApi",
	"VM_CallStack",
	"VM_Cpuid",
	"VM_Div16",
	"VM_Div32",
	"VM_Fadd",
	"VM_Fcomp",
	"VM_Fdiv",
	"VM_Fild",
	"VM_Fld",
	"VM_Fld1",
	"VM_Fldz",
	"VM_Fmul",
	"VM_Fst",
	"VM_Fstp",
	"VM_Fstsw",
	"VM_GetHash",
	"VM_Idiv32",
	"VM_Imul16",
	"VM_Imul32",
	"VM_Imul8",
	"VM_In8",
	"VM_Jmp",
	"VM_Mul16",
	"VM_Mul32",
	"VM_Nor16",
	"VM_Nor32",
	"VM_Nor8",
	"VM_PopEsp",
	"VM_PopR16",
	"VM_PopR32",
	"VM_PopR8",
	"VM_PopSp",
	"VM_Popfd",
	"VM_PushEsp",
	"VM_PushI16",
	"VM_PushI16To32",
	"VM_PushI32",
	"VM_PushI8To16",
	"VM_PushI8To32",
	"VM_PushR16",
	"VM_PushR32",
	"VM_PushSp",
	"VM_PushSs",
	"VM_Rdtsc",
	"VM_ReadDs16",
	"VM_ReadDs32",
	"VM_ReadDs8To16",
	"VM_ReadFs32",
	"VM_ReadSs16",
	"VM_ReadSs32",
	"VM_ReadSs8To16",
	"VM_Retn",
	"VM_Shl16",
	"VM_Shl32",
	"VM_Shl8",
	"VM_Shld",
	"VM_Shr16",
	"VM_Shr32",
	"VM_Shr8",
	"VM_Shrd",
	"VM_Wait",
	"VM_WriteDs16",
	"VM_WriteDs32",
	"VM_WriteDs8",
	"VM_WriteEs16",
	"VM_WriteEs32",
	"VM_WriteEs8",
	"VM_WriteFs32",
	"VM_WriteSs16",
	"VM_WriteSs32",
	"VM_WriteSs8",
};

const vm_handler_chara VmpHandler::_vmhc[] =
{
	{
		VM_PushI16,
		{
			{ "mov$ ax,word ptr ds:[esi$]" },
			{ "sub ebp,0x2" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_PushI8To32,
		{
			{ "mov al,byte ptr ds:[esi$]", "movzx eax,byte ptr ds:[esi$]" },
			{ "sub ebp,0x4" },
			{ "mov dword ptr ss:[ebp],eax" },
		}
	},
	{
		VM_Nor32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "not eax" },
			{ "not edx" },
			{ "and eax,edx" },
			{ "mov dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_ReadDs8To16,
		{
			{ "mov edx,dword ptr ss:[ebp]" },
			{ "add ebp,0x2" },
			{ "mov al,byte ptr ds:[edx]" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_GetHash,
		{
			{"mov edx,dword ptr ss:[ebp]" },
			{"shl eax,$" },
			{ "shr ecx,$", "shr edx,$" },
			{"$ eax,ecx"},
			{"mov dword ptr ss:[ebp],eax"},
		}
	},
	{
		VM_Rdtsc,
		{
			{ "rdtsc" },
			{ "mov dword ptr ss:[ebp],edx" },
			{ "mov dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_Shr16,
		{
			{ "mov ax,word ptr ss:[ebp]" },
			{ "mov cl,byte ptr ss:[ebp+0x2]" },
			{ "shr ax,cl" },
			{ "mov word ptr ss:[ebp+0x4],ax" },
		}
	},
	{
		VM_WriteSs16,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov dx,word ptr ss:[ebp+0x4]" },
			{ "add ebp,0x6" },
			{ "mov word ptr ss:[eax],dx" },
		}
	},
	{
		VM_PopR16,
		{
			{ "mov al,byte ptr ds:[esi$]", "movzx eax,byte ptr ds:[esi$]" },
			{ "mov dx,word ptr ss:[ebp]" },
			{ "add ebp,0x2" },
			{ "mov word ptr ds:[eax+edi],dx", "mov word ptr ds:[edi+eax],dx" },
		}
	},
	{
		VM_PushI32,
		{
			{ "mov eax,dword ptr ds:[esi$]" },
			{ "sub ebp,0x4" },
			{ "mov dword ptr ss:[ebp],eax" },
		}
	},
	{
		VM_PopEsp,
		{
			{ "mov ebp,dword ptr ss:[ebp]" },
		}
	},
	{
		VM_Mul32,
		{
			{ "mov edx,dword ptr ss:[ebp]" },
			{ "mov eax,dword ptr ss:[ebp+0x4]" },
			{ "mul edx" },
			{ "mov dword ptr ss:[ebp+0x4],edx" },
			{ "mov dword ptr ss:[ebp+0x8],eax" },
		}
	},
	{
		VM_ReadSs16,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov ax,word ptr ss:[eax]" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_Shr32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov cl,byte ptr ss:[ebp+0x4]" },
			{ "shr eax,cl" },
			{ "mov dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_WriteDs32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "mov dword ptr ds:[eax],edx" },
		}
	},
	{
		VM_PushEsp,
		{
			{ "mov eax,ebp" },
			{ "mov dword ptr ss:[ebp],eax" },
		}
	},
	{
		VM_PushSp,
		{
			{ "mov eax,ebp" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_WriteSs32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "mov dword ptr ss:[eax],edx" }
		}
	},
	{
		VM_ReadSs8To16,
		{
			{ "mov edx,dword ptr ss:[ebp]" },
			{ "mov al,byte ptr ss:[edx]" },
			{ "mov word ptr ss:[ebp],ax" }
		}
	},
	{
		VM_Imul32,
		{
			{ "mov edx,dword ptr ss:[ebp]" },
			{ "mov eax,dword ptr ss:[ebp+0x4]" },
			{ "imul edx" },
			{ "mov dword ptr ss:[ebp+0x4],edx" },
			{ "mov dword ptr ss:[ebp+0x8],eax" },
		}
	},
	{
		VM_Shl32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov cl,byte ptr ss:[ebp+0x4]" },
			{ "shl eax,cl" },
			{ "mov dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_Div16,
		{
			{ "mov dx,word ptr ss:[ebp]" },
			{ "mov ax,word ptr ss:[ebp+0x2]" },
			{ "mov cx,word ptr ss:[ebp+0x4]" },
			{ "div cx" }
		}
	},
	{
		VM_PopR8,
		{
			{ "mov al,byte ptr ds:[esi$]","movzx eax,byte ptr ds:[esi$]"},
			{ "mov dx,word ptr ss:[ebp]" },
			{ "mov byte ptr ds:[eax+edi],dl","mov byte ptr ds:[edi+eax],dl" },
		}
	},
	{
		VM_PushI16To32,
		{
			{ "mov$ ax,word ptr ds:[esi$]" },
			{ "sub ebp,0x4" },
			{ "mov dword ptr ss:[ebp],eax" },
		}
	},
	{
		VM_Jmp,
		{
			{ "mov esi,dword ptr ss:[ebp]"},
			{ "add esi,dword ptr ss:[ebp]" },
		}
	},
	{
		VM_WriteFs32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "mov dword ptr fs:[eax],edx" }
		}
	},
	{
		VM_Nor16,
		{
			{ "not dword ptr ss:[ebp]" },
			{ "mov ax,word ptr ss:[ebp]" },
			{ "and word ptr ss:[ebp+0x4],ax" }
		}
	},
	{
		VM_ReadSs32,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov eax,dword ptr ss:[eax]" },
			{ "mov dword ptr ss:[ebp],eax" }
		}
	},
	{
		VM_CallStack,
		{
			{ "mov edx,dword ptr ss:[ebp]" },
			{ "retn $" },
		}
	},
	{
		VM_Cpuid,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "cpuid" },
			{ "mov dword ptr ss:[ebp+0xc],eax" },
			{ "mov dword ptr ss:[ebp+0x8],ebx" },
			{ "mov dword ptr ss:[ebp+0x4],ecx" },
			{ "mov dword ptr ss:[ebp],edx" },
		}
	},
	{
		VM_PushR32,
		{
			{ "mov edx,dword ptr ds:[eax+edi]", "mov edx,dword ptr ds:[edi+eax]" },
			{ "mov dword ptr ss:[ebp],edx" },
		}
	},
	{
		VM_PushI8To16,
		{
			{ "mov al,byte ptr ds:[esi$]" , "movzx eax,byte ptr ds:[esi$]" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_Shl8,
		{
			{ "mov al,byte ptr ss:[ebp]",},
			{ "mov cl,byte ptr ss:[ebp+0x2]" },
			{ "shl al,cl" },
			{ "mov word ptr ss:[ebp+0x4],ax" }
		}
	},
	{
		VM_PushR16,
		{
			{ "movzx eax,byte ptr ds:[esi$]"},
			{ "mov ax,word ptr ds:[eax+edi]","mov ax,word ptr ds:[edi+eax]" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_Nor8,
		{
			{ "mov ax,word ptr ss:[ebp]", },
			{ "mov dx,word ptr ss:[ebp+0x2]" },
			{ "not al" },
			{ "not dl" },
			{ "and al,dl" },
			{ "mov word ptr ss:[ebp+0x4],ax" }
		}
	},
	{
		VM_Add32,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "add dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_PopSp,
		{
			{ "mov bp,word ptr ss:[ebp]", },
		}
	},
	{
		VM_Idiv32,
		{
			{ "mov edx,dword ptr ss:[ebp]", },
			{ "mov eax,dword ptr ss:[ebp+0x4]" },
			{ "idiv dword ptr ss:[ebp+0x8]" },
			{ "mov dword ptr ss:[ebp+0x4],edx" },
			{ "mov dword ptr ss:[ebp+0x8],eax" }
		}
	},
	{
		VM_WriteSs8,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov dl,byte ptr ss:[ebp+0x4]" },
			{ "mov byte ptr ss:[eax],dl" },
		}
	},
	{
		VM_ReadDs16,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov ax,word ptr ds:[eax]" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_Shld,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "mov cl,byte ptr ss:[ebp+0x8]" },
			{ "shld eax,edx,cl" },
			{ "mov dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_Shrd,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "mov cl,byte ptr ss:[ebp+0x8]" },
			{ "shrd eax,edx,cl" },
			{ "mov dword ptr ss:[ebp+0x4],eax" },
		}
	},
	{
		VM_Shl16,
		{
			{ "mov ax,word ptr ss:[ebp]", },
			{ "mov cl,byte ptr ss:[ebp+0x2]" },
			{ "shl ax,cl" },
			{ "mov word ptr ss:[ebp+0x4],ax" },
		}
	},
	{
		VM_Div32,
		{
			{ "mov edx,dword ptr ss:[ebp]", },
			{ "mov eax,dword ptr ss:[ebp+0x4]" },
			{ "div dword ptr ss:[ebp+0x8]" },
			{ "mov dword ptr ss:[ebp+0x4],edx" },
			{ "mov dword ptr ss:[ebp+0x8],eax" }
		}
	},
	{
		VM_Mul16,
		{
			{ "mov dx,word ptr ss:[ebp]", },
			{ "mov ax,word ptr ss:[ebp+0x2]" },
			{ "mul dx" },
			{ "mov word ptr ss:[ebp+0x4],dx" },
			{ "mov word ptr ss:[ebp+0x6],ax" }
		}
	},
	{
		VM_ReadDs32,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov eax,dword ptr ds:[eax]" },
			{ "mov dword ptr ss:[ebp],eax" },
		}
	},
	{
		VM_Imul16,
		{
			{ "mov dx,word ptr ss:[ebp]", },
			{ "mov ax,word ptr ss:[ebp+0x2]" },
			{ "imul dx" },
			{ "mov word ptr ss:[ebp+0x4],dx" },
			{ "mov word ptr ss:[ebp+0x6],ax" }
		}
	},
	{
		VM_Imul8,
		{
			{ "mov dl,byte ptr ss:[ebp]", },
			{ "mov al,byte ptr ss:[ebp+0x2]" },
			{ "imul dl" },
			{ "mov word ptr ss:[ebp+0x4],ax" },
		}
	},
	{
		VM_WriteDs8,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov dl,byte ptr ss:[ebp+0x4]" },
			{ "mov byte ptr ds:[eax],dl" },
		}
	},
	{
		VM_Add8,
		{
			{ "mov al,byte ptr ss:[ebp]", },
			{ "add byte ptr ss:[ebp+0x4],al" },
		}
	},
	{
		VM_WriteEs32,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov edx,dword ptr ss:[ebp+0x4]" },
			{ "mov dword ptr es:[eax],edx" }
		}
	},
	{
		VM_ReadFs32,
		{
			{ "mov eax,dword ptr ss:[ebp]", },
			{ "mov eax,dword ptr fs:[eax]" },
			{ "mov dword ptr ss:[ebp],eax" }
		}
	},
	{
		VM_Retn,
		{
			{ "mov esp,ebp" },
			{ "retn $" },
		}
	},
	{
		VM_Shr8,
		{
			{ "mov al,byte ptr ss:[ebp]" },
			{ "mov cl,byte ptr ss:[ebp+0x2]" },
			{ "shr al,cl" },
			{ "mov word ptr ss:[ebp+0x4],ax" }
		}
	},
	{
		VM_Add16,
		{
			{ "mov ax,word ptr ss:[ebp]" },
			{ "add word ptr ss:[ebp+0x4],ax" },
		}
	},
	{
		VM_CallApi,
		{
			{ "xchg dword ptr ss:[ebp+ecx*4$],eax" },
			{ "retn $" }
		}
	},
	{
		VM_WriteDs16,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov dx,word ptr ss:[ebp+0x4]" },
			{ "mov word ptr ds:[eax],dx" }
		}
	},
	{
		VM_PopR32,
		{
			//{ "movzx eax,byte ptr ds:[esi$]" },
			{ "mov edx,dword ptr ss:[ebp]" },
			{ "mov dword ptr ds:[eax+edi],edx", "mov dword ptr ds:[edi+eax],edx" }
		}
	},
	{
		VM_Popfd,
		{
			{ "push dword ptr ss:[ebp]" },
			{ "popfd" },
		}
	},
	{
		VM_PushSs,
		{
			{ "mov ax,ss" },
			{ "mov word ptr ss:[ebp],ax" },
		}
	},
	{
		VM_WriteEs16,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov dx,word ptr ss:[ebp+0x4]" },
			{ "mov word ptr es:[eax],dx" }
		}
	},
	{
		VM_WriteEs8,
		{
			{ "mov eax,dword ptr ss:[ebp]" },
			{ "mov dl,byte ptr ss:[ebp+0x4]" },
			{ "mov byte ptr es:[eax],dl" }
		}
	},
	{
		VM_In8,
		{
			{ "mov dx,word ptr ss:[ebp]" },
			{ "in eax,dx" },
			{ "mov dword ptr ss:[ebp],eax" }
		}
	},
	{
		VM_Fild,
		{
			{ "fild dword ptr ss:[ebp]" },
		}
	},
	{
		VM_Fld,
		{
			{ "fld $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fld1,
		{
			{ "fld1" },
		}
	},
	{
		VM_Fldz,
		{
			{ "fldz" },
		}
	},
	{
		VM_Fmul,
		{
			{ "fmul $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fstp,
		{
			{ "fstp $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fst,
		{
			{ "fst $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fadd,
		{
			{ "fadd $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fcomp,
		{
			{ "fcomp $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fdiv,
		{
			{ "fdiv $ ptr ss:[ebp]" },
		}
	},
	{
		VM_Fstsw,
		{
			{ "fstsw $" },
		}
	},
	{
		VM_Wait,
		{
			{ "wait" },
		}
	},
};


bool strMatch(const char* str0, const char* str1)
{
	const char* tmp0 = str0;
	const char* tmp1 = str1;
	while (*tmp0)
	{
		if (*tmp0 != *tmp1)
		{
			if (*tmp0 == '$')
			{
				tmp0++;
				while (*tmp1 && *tmp1 != ']' && *tmp1 != ' ')
				{
					tmp1++;
				}
				continue;
			}
			return false;
		}
		tmp0++;
		tmp1++;
	}
	if (*tmp0|*tmp1)
		return false;
	return true;
}


vm_handler VmpHandler::MatchHandler(Inst_UD_Chain* chain)
{
	
	for (int i = 0; i < sizeof(_vmhc) / sizeof(vm_handler_chara); i++)
	{
		ulong cindex = 0;
		chara_unit pch = _vmhc[i].chara[cindex];
		Inst_UD_Node* tmp = chain->GetHeader();
		while (pch.ch[0] && tmp)
		{
				_strlwr(tmp->cmdInfo.cmd);
				ulong ccindex = 0;
				while (ccindex<3 && pch.ch[ccindex])
				{
					if (strMatch(pch.ch[ccindex],tmp->cmdInfo.cmd))
					{
						cindex++;
						pch = _vmhc[i].chara[cindex];
						break;
					}
					ccindex++;
				}
			tmp = tmp->nextNode;
		}
		if (!pch.ch[0])
		{
			return _vmhc[i].handler;
		}
	}
	return VM_Unknown;
}
