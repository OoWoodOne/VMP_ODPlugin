#ifndef _ANTI_OBSCURE_
#define _ANTI_OBSCURE_
#include "AsmForm.h"


struct Inst_UD_Node
{
	Inst_UD_Node* preNode;
	Inst_UD_Node* nextNode;


	bool isDiscarded;//ture if earse.

	ulong opDef;//oprand def
	ulong opRef;//oprand ref
	int stackDef;//stack def
	
	int espPos;
	int espPosDef;
	int espPosRef;
	int espPosRRef;

	int ebpPosDef;
	int ebpPosRef;

	cmd_info cmdInfo;
};

class Inst_UD_Chain
{
protected:
	Inst_UD_Node* _header;
	Inst_UD_Node* _tail;
	int _esp_pos;
public:	
	Inst_UD_Chain();
	~Inst_UD_Chain();
	//get chain header.
	Inst_UD_Node* GetHeader(){ return _header; };
	//get chain tail.
	Inst_UD_Node* GetTail(){ return _tail; };
	//get chain end esppos.
	int GetEspPos(){ return _esp_pos; };
	//add node with analyse ud automatically.
	bool AddNode(t_disasm* disasm, void* cmdBuf, ulong cmdLen,bool optimize=true);
	//add node.
	bool AddNode(Inst_UD_Node* node, bool optimize = true);
	//optimize the ud chain.
	void OptimizeUD(Inst_UD_Node* node);
	//optimize the stack.
	void OptimizeStack();
	//optimize the chain.
	void OptimizeChain();
	//delete node.
	bool DeleteNode(Inst_UD_Node* node);
	//clear chain.
	void ClearChain();
	//find node by ip
	Inst_UD_Node* FindNode(ulong ip);
	//print instructions.
	void PrintChain(bool showDiscard=false,bool showArg=false);
	//analyse ud, return node.
	Inst_UD_Node* AnalyseUD(t_disasm* disasm, void* cmdBuf, ulong cmdLen);

};




#endif