#ifndef _LOG_WINDOW_
#define _LOG_WINDOW_
#include "Plugin.h"

#define LOG_NORMAL			0x0000
#define LOG_HILITE			0x0001
#define LOG_GRAY			0x0002
#define LOG_TITLE_SPREAD    0x0004
#define LOG_TITLE_INDENT    0x0008
#define LOG_TITLE			0x000C
#define LOG_TITLE_END		0x0010
#define LOG_TITLE_SUB		0x0020


struct log_data
{
	ulong index;
	ulong size;
	ulong type;
	ulong addr;
	int mode;
	//use for title
	log_data* subDataHeadler;
	log_data* subDataTail;
	log_data* nextData;
	char *info;
 	char *note;
};

#define CREATE_LOGFILE LogWindow::CreateLogFile
#define LOG2FILE LogWindow::LogToFile
#define CLOSE_LOGFILE LogWindow::CloseLogFile

#define LOG LogWindow::AddToLog
#define LOGTITLE(x) LOG(0,x,NULL,LOG_TITLE_INDENT)
#define LOGTITLEEND LOG(0,NULL,NULL,LOG_TITLE_END)
#define LOGERROR(x) LOG(0,x,NULL,LOG_HILITE)
//only use once for one proc.
#define LSFI LogWindow::LogSprintfI
#define LSFN LogWindow::LogSprintfN
class LogWindow
{
public:
	static char* _logWindowName;
	static char  LogWindowWinclass[32];
	static t_table _logTable;
	static char _logSprintfBufI[TEXTLEN];
	static char _logSprintfBufN[TEXTLEN];
	static HINSTANCE _hinst;
	static ulong _logIndex;
	static ulong _titleIndex;
	static log_data* _curTitle;

	static LRESULT CALLBACK LogWindowProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp);
	static int LogSortFunc(const t_sortheader *p1, const t_sortheader *p2, const int sort);
	static void LogDestFunc(t_sortheader *pe);
	static int LogWindowGetText(char *s, char *mask, int *select, t_sortheader *ph, int column);
	static bool CreateLogWindow(HINSTANCE hinst);
	static void DestroyLogWindow();
	static void AddToLog(ulong addr,const char* info,const char* note=NULL,int mode=LOG_NORMAL);
	static void ShowLogWindow();
	static char* LogSprintfI(const char* format, ...);
	static char* LogSprintfN(const char* format, ...);
	static void Clear();


	static HANDLE CreateLogFile(const char* filename);
	static void LogToFile(HANDLE file, const char* format, ...);
	static void CloseLogFile(HANDLE file);
};


#endif