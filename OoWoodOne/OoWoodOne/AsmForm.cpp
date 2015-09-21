#include <Windows.h>

#include "AsmForm.h"

ulong RegType2RegIndex(ulong regType)
{
	int ret=REG_EAX;
	ulong tmp = regType;
	while (tmp)
	{	
		
		if (tmp & 0x0000000F)
		{
			return ret;
		}
		tmp >>= 4;
		ret++;
	}
	return REG_INDEX_NONE;
}

opcode_type FindAsmOpt(const char* keyWord)
{
	int left = 0, right = ASM_XSAVES - 1, mid = 0;
	mid = (left + right) / 2;
	int cmp = _stricmp(keyWord, ASM_OPT_KEY[mid]);
	while (left < right && cmp)
	{
		if (cmp>0)
			left = mid + 1;
		else
			right = mid - 1;
		mid = (left + right) / 2;
		cmp = _stricmp(keyWord, ASM_OPT_KEY[mid]);
	}
	if (!cmp)
		return (opcode_type)(mid + 1);
	return ASM_NONE;
}

//get opt
opcode_type GetOpcodeType(const char* text)
{
	char keyword[TEXTLEN];
	const char* tmp = text;
	int keylen = 0;
	opcode_type ret;
	while (*tmp && *tmp != ' ')
	{
		tmp++;
	}
	keylen = tmp - text;
	if (keylen == 0)
	{
		return ASM_NONE;
	}
	else
	{
		memcpy(keyword, text, tmp - text);
		keyword[keylen] = 0;
		ret = FindAsmOpt(keyword);
		if (ret == ASM_NONE)
		{
			//may be the prefix
			const char* tmp1 = tmp;
			while (*tmp1 && *tmp1 != ' ')
			{
				tmp1++;
			}
			keylen = tmp1 - tmp;
			if (keylen == 0)
			{
				return ASM_NONE;
			}
			else
			{
				memcpy(keyword, text, tmp - text);
				keyword[keylen - 1] = 0;
				ret = FindAsmOpt(keyword);
			}
		}
	}
	return ret;
}

//convert regscale to ud_type.
ulong Regscale2Regtype(t_operand* op)
{
	ulong ret = 0, tmp = 0, i = 0;
	while (i < 8)
	{
		if (op->regscale[i])
		{
			if (op->seg == 0xFF)
			{
				if (op->opsize == 1)
				{
					tmp = (op->regscale[i] << (i / 4)) << (i % 4) * 4;
				}
				else
				{
					tmp = 0x00000007 >> (i / 4) >> ((4 - op->opsize) / 2) << i * 4;
				}
			}
			else
			{
				tmp = 0x00000007 >> (i / 4) << i * 4;
			}

			ret |= tmp;
		}
		i++;
	}
	return ret;
}

void convertDisasm2Cmdinfo(t_disasm* disasm, void* cmdbuf, ulong cmdlen, cmd_info* cmdinfo)
{
	cmdinfo->ip = disasm->ip;
	cmdinfo->cmdLen = cmdlen;
	memcpy(cmdinfo->cmdBuf, cmdbuf, cmdlen);
	strcpy(cmdinfo->cmd, disasm->result);
	cmdinfo->optType = GetOpcodeType(disasm->result);
	for (int i = 0; i < 3; i++)
	{
		if (!disasm->op[i].opsize)
			break;
		cmdinfo->op[i].reg = Regscale2Regtype(&disasm->op[i]);
		if (disasm->op[i].seg != 0xFF)
		{
			cmdinfo->op[i].opType |= OP_MEM;
		}
		else if (cmdinfo->op[i].reg)
		{
			cmdinfo->op[i].opType |= OP_REG;
		}
		else
		{
			cmdinfo->op[i].opType |= OP_IMM;
		}

		cmdinfo->op[i].opType |= (OP_BYTE << (disasm->op[i].opsize/2));
		cmdinfo->op[i].opConst = disasm->op[i].opconst;
	}

}

const char* ASM_REG_KEY[] =
{
	"EAX",
	"ECX",
	"EDX",
	"EBX",
	"ESP",
	"EBP",
	"ESI",
	"EDI",
	"EIP"
};

const char* ASM_OPT_KEY[] =
{
	"AAA",
	"AAD",
	"AAM",
	"AAS",
	"ADC",
	"ADD",
	"AND",
	"BSF",
	"BSR",
	"BSWAP",
	"BT",
	"BTC",
	"BTR",
	"BTS",
	"CALL",
	"CBW",
	"CDQ",
	"CLC",
	"CLD",
	"CLI",
	"CLTS",
	"CMC",
	"CMOVA",
	"CMOVAE",
	"CMOVB",
	"CMOVBE",
	"CMOVC",
	"CMOVE",
	"CMOVG",
	"CMOVGE",
	"CMOVL",
	"CMOVLE",
	"CMOVNA",
	"CMOVNAE",
	"CMOVNB",
	"CMOVNBE",
	"CMOVNC",
	"CMOVNE",
	"CMOVNG",
	"CMOVNGE",
	"CMOVNL",
	"CMOVNLE",
	"CMOVNO",
	"CMOVNP",
	"CMOVNS",
	"CMOVNZ",
	"CMOVO",
	"CMOVP",
	"CMOVPE",
	"CMOVPO",
	"CMOVS",
	"CMOVZ",
	"CMP",
	"CMPS",
	"CMPSB",
	"CMPSD",
	"CMPSW",
	"CMPXCHG",
	"CPUID",
	"CWD",
	"CWDE",
	"DAA",
	"DAS",
	"DEC",
	"DIV",
	"ENTER",
	"HLT",
	"IDIV",
	"IMUL",
	"IN",
	"INC",
	"INS",
	"INSB",
	"INSD",
	"INSW",
	"INT",
	"INT3",
	"INTO",
	"INVD",
	"INVLPG",
	"IRET",
	"IRETD",
	"IRETW",
	"JA",
	"JAE",
	"JB",
	"JBE",
	"JC",
	"JCXZ",
	"JE",
	"JECXZ",
	"JG",
	"JGE",
	"JL",
	"JLE",
	"JMP",
	"JNA",
	"JNAE",
	"JNB",
	"JNBE",
	"JNC",
	"JNE",
	"JNG",
	"JNGE",
	"JNL",
	"JNLE",
	"JNO",
	"JNP",
	"JNS",
	"JNZ",
	"JO",
	"JP",
	"JPE",
	"JPO",
	"JS",
	"JZ",
	"LAHF",
	"LAR",
	"LDS",
	"LEA",
	"LEAVE",
	"LES",
	"LFENCE",
	"LFS",
	"LGDT",
	"LGS",
	"LIDT",
	"LLDT",
	"LMSW",
	"LODS",
	"LODSB",
	"LODSD",
	"LODSW",
	"LOOP",
	"LOOPE",
	"LOOPNE",
	"LSL",
	"LSS",
	"LTR",
	"MOV",
	"MOVBE",
	"MOVNTI",
	"MOVS",
	"MOVSB",
	"MOVSD",
	"MOVSW",
	"MOVSX",
	"MOVZX",
	"MUL",
	"MWAIT",
	"NEG",
	"NOP",
	"NOT",
	"OR",
	"OUT",
	"OUTS",
	"OUTSB",
	"OUTSD",
	"OUTSW",
	"PAUSE",
	"POP",
	"POPA",
	"POPAD",
	"POPAW",
	"POPCNT",
	"POPF",
	"POPFD",
	"POPFW",
	"PREFETCHNTA",
	"PREFETCHT0",
	"PREFETCHT1",
	"PREFETCHT2",
	"PUSH",
	"PUSHA",
	"PUSHAD",
	"PUSHAW",
	"PUSHF",
	"PUSHFD",
	"PUSHFW",
	"RCL",
	"RCR",
	"RDMSR",
	"RDPMC",
	"RDTSC",
	"RDTSCP",
	"RET",
	"RETN",
	"ROL",
	"ROR",
	"RSM",
	"SAHF",
	"SAL",
	"SAR",
	"SBB",
	"SCAS",
	"SCASB",
	"SCASD",
	"SCASW",
	"SETA",
	"SETAE",
	"SETB",
	"SETBE",
	"SETC",
	"SETE",
	"SETG",
	"SETGE",
	"SETL",
	"SETLE",
	"SETNA",
	"SETNAE",
	"SETNB",
	"SETNBE",
	"SETNC",
	"SETNE",
	"SETNG",
	"SETNGE",
	"SETNL",
	"SETNLE",
	"SETNO",
	"SETNP",
	"SETNS",
	"SETNZ",
	"SETO",
	"SETP",
	"SETPE",
	"SETPO",
	"SETS",
	"SETZ",
	"SFENCE",
	"SGDT",
	"SHL",
	"SHLD",
	"SHR",
	"SHRD",
	"SIDT",
	"SLDT",
	"SMSW",
	"STAC",
	"STC",
	"STD",
	"STI",
	"STOS",
	"STOSB",
	"STOSD",
	"STOSW",
	"STR",
	"SUB",
	"SYSCALL",
	"SYSENTER",
	"SYSEXIT",
	"SYSRET",
	"TEST",
	"UD2",
	"VERR",
	"VERW",
	"WAIT",
	"WBINVD",
	"WRMSR",
	"XADD",
	"XCHG",
	"XGETVB",
	"XLATB",
	"XOR",
	"XRSTOR",
	"XRSTORS",
	"XSAVE",
	"XSAVEC",
	"XSAVES",
};