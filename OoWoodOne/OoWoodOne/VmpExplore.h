#ifndef _VMP_EXPLORE_
#define _VMP_EXPLORE_
#include "AntiObscure.h"
#include "VmpHandler.h"

#define MAX_VM_RET_CONTEXT_COUNT 0x10
#define MAX_VM_CONTEXT_COUNT 0xD
#define MIN_VM_CONTEXT_COUNT 0xC
#define MAX_VMP_ENTRY_CMD_COUNT 300
#define MAX_VMP_FIX_API_CMD_COUNT 100
struct vmp_cxt_unit
{
	ulong value;
	char remark[20];
};

struct simple_cmd_info
{
	simple_cmd_info* preCmd;
	simple_cmd_info* nextCmd;
	cmd_info cmdInfo;
	char note[TEXTLEN];
};

struct simple_cmd_group
{
	simple_cmd_info* header;
	simple_cmd_info* tail;
};

void earseCmdGroup(simple_cmd_group* g);
void addCmdToGroup(simple_cmd_group* g, simple_cmd_info* c);
simple_cmd_info* createCmdFromUDNode(Inst_UD_Node* node, const char* note = NULL);

struct vmp_dispatch_info
{
	ulong tableBase;
	ulong idspReg;
	ulong indexReg;

	ulong opcodeDecodeReg;
	ulong opcodeJoinReg;

	ulong opcodeLoadIP;
	int esiOffset;
	int esiChange;
	simple_cmd_info dispatchCmd;
	simple_cmd_group opcodeDecode;
};

struct vmp_initkey_info
{
	ulong initkeyValue;
	ulong initkeyDecodeReg;
	ulong relocJoinReg;
	simple_cmd_group initkeyDecode;
};


struct vmp_handler
{
	ulong orgData;
	ulong addr;
	bool isCopy;
	Inst_UD_Chain* handlerChain;
	simple_cmd_group handlerCmds;
	ulong handler;
};

struct vmp_handler_addr
{
	ulong addr;
	Inst_UD_Chain* chain;
	vmp_handler_addr* next;
	Inst_UD_Node* DataLoad;
	int esiChange;
	int ebpChange;
	int esiOffset;
	ulong esiOffsetDigit;//op_type
	simple_cmd_group dataDecode;
};

#define VMP_HANDLER_DECODE_CONST 0xFF+1

struct code_handle
{
	void* baseAddr;
	ulong inOffset;
	ulong inOffset2;
	ulong outOffset;
	ulong outOffset2;
};

typedef void(*PF)();

struct hash_info
{
	ulong vm_eip;
	ulong hash_value;
	ulong tableBase;
	ulong tableSize;
	ulong tableValue;
};
#define VMP_PATCH_HASH_DATA_SIZE 0x1000

struct vmp_patch_hash
{
	ulong progress;
	ulong addr_MapViewOfFile;
	ulong addr_GetHash;
	ulong addr_ReadDs32;

	ulong fileMapAddr;

};


class VmpExplore
{

protected:
	int _progress;
	Inst_UD_Chain* _entryChain;
	int _contextCount;
	vmp_cxt_unit _context[MAX_VM_CONTEXT_COUNT];
	vmp_cxt_unit _retContext[MAX_VM_RET_CONTEXT_COUNT];
	vmp_initkey_info _initkeyInfo;
	vmp_dispatch_info _dispatchInfo;
	simple_cmd_group _handlerDecode;
	simple_cmd_group _vmEntry;
	simple_cmd_info _checkEsp;
	vmp_handler _handlers[VMP_HANDLER_DECODE_CONST];
	vmp_handler_addr* _handlersAddr[vm_handler::VMH_End];
	//

	vmp_patch_hash _patchHashData;
	ULONG _patchHashDataAddr;
	//
	
	Inst_UD_Chain* ReadHandlerCmdChain(ulong addr, bool mode = true, int maxCmdCount = MAX_VMP_ENTRY_CMD_COUNT);
	bool GetVMhandlerEntry(ulong addr);

	static bool JccJump(ulong jcc,Inst_UD_Node* eflCmd,int* isJmp);//isJmp=0 no jmp, 1 jmp ,-1 unknown

	bool AnalyseEntry(ulong addr = 0);
	bool AnalyseInitkeyInfo();
	bool AnalyseDispatchInfo(Inst_UD_Chain* chain,bool foundJoinReg=true);
	bool AnalyseHandlerDecode();
	bool AnalyseContext();
	bool AnalyseHandlers();
	bool AnalyseRetContext();
	bool ReAnalyseDispatchInfo();//reanalyse dispatch info by handler commands.
	bool AnalyseEntryCode();

	code_handle* CreateCodeHandle(simple_cmd_group *cmdGroup, ulong inReg, ulong outReg);
	code_handle* CreateCodeHandle2(simple_cmd_info* inst, ulong Reg1, ulong Reg2);
	void FreeCodeHandle(code_handle* ch);
	ulong DoCodeHandle(code_handle* ch, ulong dataIn);
	void DoCodeHandle2(code_handle* ch, ulong dataIn,ulong dataIn2,ulong*dataOut,ulong*dataOut2);

	bool VMPFindHandlerEsiOffset(vmp_handler_addr* vmhAddr);
	bool VMPFindHandlerEsiEbpChange(vmp_handler_addr* vmhAddr);
	bool VMPGetHandlerDataDecode(vmp_handler_addr* vmhAddr);
	bool VMPGetHandlerDataDecode2(vmp_handler_addr* vmhAddr);
public:
	VmpExplore();
	~VmpExplore();
	bool AnalyseVMP(ulong addr=0);
	void PrintVMPInfo();
	void PrintInitkeyInfo();
	void PrintDispatchInfo();
	void PrintHandlerDecode();
	void PrintCheckEsp();
	void PrintContext();
	void PrintVMEntry();
	void PrintHandlers();
	void PrintHandlersAddr();
	void PrintRetContext();
	void Clear();
	ulong GetStartAddress();
	static Inst_UD_Chain* ReadCmdChain(ulong addr = 0, bool optimize = true, int maxCmdCount = MAX_VMP_ENTRY_CMD_COUNT, bool showLog = true);

	//do
	bool VmpPatchHash();
	bool Do_VmpPatchHash();
	
	bool VmpToOEPWithPathAntiDump();

	bool VmpAnalyseCode(ulong vmEip,ulong joinRegValue,int vmEspStart=0);
	
	

	static BOOL VmpFixApiUnit(ulong addr, t_module* module,HANDLE logfile);
	static bool VmpFixApi(ulong addr);//修复给定地址的区段api

	bool IsVMHandler(ulong addr, vm_handler vh);
	ulong GetVMHandlerAddr(vm_handler vh){ return _handlersAddr[vh]?_handlersAddr[vh]->addr:0; };
	ulong GetVMReloc(){ return _context[0].value; };
};


#endif