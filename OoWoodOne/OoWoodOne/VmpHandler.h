#ifndef _VMP_HANDLER_
#define _VMP_HANDLER_
#include "AntiObscure.h"

enum vm_handler
{
	VM_Unknown,
	VM_Invalid,
	VM_Add16,
	VM_Add32,
	VM_Add8,
	VM_CallApi,
	VM_CallStack,
	VM_Cpuid,
	VM_Div16,
	VM_Div32,
	VM_Fadd,
	VM_Fcomp,
	VM_Fdiv,
	VM_Fild,
	VM_Fld,
	VM_Fld1,
	VM_Fldz,
	VM_Fmul,
	VM_Fst,
	VM_Fstp,
	VM_Fstsw,
	VM_GetHash,
	VM_Idiv32,
	VM_Imul16,
	VM_Imul32,
	VM_Imul8,
	VM_In8,
	VM_Jmp,
	VM_Mul16,
	VM_Mul32,
	VM_Nor16,
	VM_Nor32,
	VM_Nor8,
	VM_PopEsp,
	VM_PopR16,
	VM_PopR32,
	VM_PopR8,
	VM_PopSp,
	VM_Popfd,
	VM_PushEsp,
	VM_PushI16,
	VM_PushI16To32,
	VM_PushI32,
	VM_PushI8To16,
	VM_PushI8To32,
	VM_PushR16,
	VM_PushR32,
	VM_PushSp,
	VM_PushSs,
	VM_Rdtsc,
	VM_ReadDs16,
	VM_ReadDs32,
	VM_ReadDs8To16,
	VM_ReadFs32,
	VM_ReadSs16,
	VM_ReadSs32,
	VM_ReadSs8To16,
	VM_Retn,
	VM_Shl16,
	VM_Shl32,
	VM_Shl8,
	VM_Shld,
	VM_Shr16,
	VM_Shr32,
	VM_Shr8,
	VM_Shrd,
	VM_Wait,
	VM_WriteDs16,
	VM_WriteDs32,
	VM_WriteDs8,
	VM_WriteEs16,
	VM_WriteEs32,
	VM_WriteEs8,
	VM_WriteFs32,
	VM_WriteSs16,
	VM_WriteSs32,
	VM_WriteSs8,
	VMH_End,
};

struct chara_unit
{
	const char * ch[3];
};

struct vm_handler_chara
{
	vm_handler handler;
	chara_unit chara[10];
};

class VmpHandler
{

protected:
	static const char* _vmh[];
	static const vm_handler_chara _vmhc[];
public:
	static vm_handler MatchHandler(Inst_UD_Chain* chain);
	static const char* GetHandler(vm_handler vmh){ return _vmh[vmh]; };
	
};

#endif