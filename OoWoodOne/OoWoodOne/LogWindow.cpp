#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>
#include "LogWindow.h"


char* LogWindow::_logWindowName = "OoWoodOne Log";
t_table LogWindow::_logTable = { 0 };
char  LogWindow::LogWindowWinclass[32] = { 0 };
char LogWindow::_logSprintfBufI[TEXTLEN] = { 0 };
char LogWindow::_logSprintfBufN[TEXTLEN] = { 0 };
HINSTANCE LogWindow::_hinst = 0;
ulong LogWindow::_logIndex = 0;
ulong LogWindow::_titleIndex = 0;
log_data* LogWindow::_curTitle = NULL;

LRESULT CALLBACK LogWindow::LogWindowProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
	int i;
	HMENU menu;
	log_data *ld;
	switch (msg)
	{
	case WM_DESTROY:
	case WM_MOUSEMOVE:
	case WM_LBUTTONDOWN:
	case WM_LBUTTONDBLCLK:
	case WM_LBUTTONUP:
	case WM_RBUTTONDOWN:
	case WM_RBUTTONDBLCLK:
	case WM_HSCROLL:
	case WM_VSCROLL:
	case WM_TIMER:
	case WM_SYSKEYDOWN:
		Tablefunction(&_logTable, hw, msg, wp, lp);
		break;
	case WM_USER_SCR:
	case WM_USER_VABS:
	case WM_USER_VREL:
	case WM_USER_VBYTE:
	case WM_USER_STS:
	case WM_USER_CNTS:
	case WM_USER_CHGS:
		return Tablefunction(&_logTable, hw, msg, wp, lp);
	case WM_WINDOWPOSCHANGED:
		return Tablefunction(&_logTable, hw, msg, wp, lp);
	case WM_USER_MENU:
		menu = CreatePopupMenu();
		ld = (log_data *)Getsortedbyselection(&(_logTable.data), _logTable.data.selected);
		if (menu != NULL && ld != NULL) 
		{
			if (ld->addr)
			{
				AppendMenu(menu, MF_STRING, 1, "&Follow to disassembler");
				AppendMenu(menu, MF_STRING, 2, "&Follow to dump");
			}
			else if (ld->mode&LOG_TITLE_INDENT)
			{
				AppendMenu(menu, MF_STRING, 3, "&Spread");
				AppendMenu(menu, MF_STRING, 5, "&Delete");
			}
			else if (ld->mode&LOG_TITLE_SPREAD)
			{
				AppendMenu(menu, MF_STRING, 4, "&Indent");
				AppendMenu(menu, MF_STRING, 5, "&Delete");
			}
			AppendMenu(menu, MF_STRING, 20, "&Clear Window\t");
		};
		i = Tablefunction(&_logTable, hw, WM_USER_MENU, 0, (LPARAM)menu);

		if (menu != NULL) 
			DestroyMenu(menu);

		switch (i)
		{
		case 1:
		{
			Setcpu(0, ld->addr, 0, 0, CPU_ASMHIST | CPU_ASMCENTER | CPU_ASMFOCUS);
			break;
		}
		case 2:
		{
			Setcpu(0, 0, ld->addr, 0, CPU_DUMPHIST | CPU_DUMPFIRST | CPU_DUMPFOCUS);
			break;
		}
		case 3:
		{
			ld->mode = LOG_TITLE_SPREAD;
			log_data* tmp = ld->subDataHeadler;
			while (tmp)
			{
				Addsorteddata(&(_logTable.data), tmp);
				tmp = tmp->nextData;
			}
			InvalidateRect(hw, NULL, FALSE);
			break;
		}
		case 4:
		{
			ld->mode = LOG_TITLE_INDENT;
			if (ld->subDataHeadler)
			{
				Deletesorteddatarange(&(_logTable.data), ld->subDataHeadler->index-1, ld->subDataTail->index+1);
			}
			InvalidateRect(hw, NULL, FALSE);
			break;
		}
		case 5:
		{
			if (ld->mode == LOG_TITLE_SPREAD && ld->subDataHeadler)
			{
				Deletesorteddatarange(&(_logTable.data), ld->subDataHeadler->index - 1, ld->subDataTail->index + 1);
			}
			Deletesorteddatarange(&(_logTable.data), ld->index - 1, ld->index + 1);
			InvalidateRect(hw, NULL, FALSE);
			break;
		}
		case 20:
		{
			Clear();
			InvalidateRect(hw, NULL, FALSE);
			break;
		}
		default:
			break;
		}
		return 0;
	case WM_KEYDOWN:
		Tablefunction(&_logTable, hw, msg, wp, lp);
		break;
	case WM_USER_DBLCLK:
		ld = (log_data *)Getsortedbyselection(&(_logTable.data), _logTable.data.selected);
		if (ld)
		{
			if (ld->mode & LOG_TITLE_INDENT)
			{
				ld->mode = LOG_TITLE_SPREAD;
				log_data* tmp = ld->subDataHeadler;
				while (tmp)
				{
					Addsorteddata(&(_logTable.data), tmp);
					tmp = tmp->nextData;
				}
				InvalidateRect(hw, NULL, FALSE);
			}
			else if (ld->mode & LOG_TITLE_SPREAD)
			{
				ld->mode = LOG_TITLE_INDENT;
				if (ld->subDataHeadler)
				{
					Deletesorteddatarange(&(_logTable.data), ld->subDataHeadler->index-1, ld->subDataTail->index+1);
				}
				InvalidateRect(hw, NULL, FALSE);
			}
			else if (ld->addr)
			{
				Setcpu(0, ld->addr, 0, 0, CPU_ASMHIST | CPU_ASMCENTER | CPU_ASMFOCUS);
			}
		}
		return 1;
	case WM_USER_CHALL:
	case WM_USER_CHMEM:
		InvalidateRect(hw, NULL, FALSE);
		return 0;
	case WM_PAINT:
		Painttable(hw, &_logTable, LogWindowGetText);
		return 0;
	default: 
		break;
	};
	return DefMDIChildProc(hw, msg, wp, lp);
}

int LogWindow::LogWindowGetText(char *s, char *mask, int *select, t_sortheader *ph, int column)
{
	int n = 0;
	log_data *ld = (log_data *)ph;
	*select = DRAW_NORMAL;
	if (ld->mode == LOG_TITLE_END)
	{
		return n;
	}


	if (column == 0) //addr
	{
		if (ld->mode & LOG_TITLE)
		{
			*select = DRAW_EIP;
		}
		if (ld->mode&LOG_TITLE_INDENT)
		{
			strcpy(s, "      +");
			n = strlen(s);
		}
		else if (ld->mode&LOG_TITLE_SPREAD)
		{
			strcpy(s, "      -");
			n = strlen(s);
		}
		else if (ld->addr)
		{
			*select = DRAW_GRAY;
			n = sprintf(s, "%08X", ld->addr);
		}


	}
	else if (column == 1 && ld->info)//info text
	{
		if (ld->mode == LOG_HILITE)
		{
			*select = DRAW_HILITE;
		}
		else if (ld->mode == LOG_GRAY)
		{
			*select = DRAW_GRAY;
		}
		else if (ld->mode & LOG_TITLE)
		{
			*select = DRAW_GRAY;
		}
		strcpy(s, ld->info);
		n = strlen(s);
	}
		
	else if (column == 2 && ld->note)
	{ 
		//*select = DRAW_GRAY;
		strcpy(s, ld->note);
		n = strlen(s);
	}
	else
	{
		n = 0;
	}
	return n;
}

int LogWindow::LogSortFunc(const t_sortheader *p1, const t_sortheader *p2, const int sort)
{
	if (p1->addr<p2->addr)
		return -1;
	else if (p1->addr>p2->addr)
		return 1;
	return 0;
};

void LogWindow::LogDestFunc(t_sortheader *pe)
{
	log_data* ld = (log_data*)pe;
	if (ld->subDataHeadler)
	{
		log_data* tmp = ld->subDataHeadler;
		log_data* tmp0;
		while (tmp)
		{
			tmp0 = tmp->nextData;
			if (tmp->info)
			{
				delete[] tmp->info;
			}
			if (tmp->note)
			{
				delete[] tmp->note;
			}
			delete tmp;
			tmp = tmp0;
		}
	}
	if (ld->mode != LOG_TITLE_SUB)
	{
		if (ld->info)
		{
			delete[] ld->info;
		}
		if (ld->note)
		{
			delete[] ld->note;
		}
	}
}

bool LogWindow::CreateLogWindow(HINSTANCE hinst)
{
	_hinst = hinst;
	if (Createsorteddata(&(_logTable.data), _logWindowName, sizeof(log_data), 10, (SORTFUNC *)LogSortFunc, (DESTFUNC*)LogDestFunc) != 0)
	{
		return false;
	}
	if (Registerpluginclass(LogWindowWinclass, NULL, hinst, LogWindowProc)<0)
	{
		Destroysorteddata(&(_logTable.data));
		return false;
	};

		if (_logTable.bar.nbar == 0)
		{
			_logTable.bar.name[0] = "Address";
			_logTable.bar.defdx[0] = 9;
			_logTable.bar.mode[0] = BAR_NOSORT;
			_logTable.bar.name[1] = "Info";
			_logTable.bar.defdx[1] = 40;
			_logTable.bar.mode[1] = BAR_NOSORT;
			_logTable.bar.name[2] = "Note";
			_logTable.bar.defdx[2] = 256;
			_logTable.bar.mode[2] = BAR_NOSORT;
			_logTable.bar.nbar = 3;
			_logTable.mode = TABLE_COPYMENU | TABLE_APPMENU | TABLE_SAVEPOS | TABLE_ONTOP ;
			_logTable.drawfunc = LogWindowGetText;
		}
		//Newtablewindow(&_logTable, 15, 3, LogWindowWinclass, _logWindowName);
		return true;
}

void LogWindow::DestroyLogWindow()
{
	Unregisterpluginclass(LogWindowWinclass);
	Destroysorteddata(&(_logTable.data));
}

void LogWindow::AddToLog(ulong addr, const char* info, const char* note, int mode)
{

	log_data *ld=new log_data;
	memset(ld, 0, sizeof(log_data));
	_logIndex++;
	ld->index = _logIndex;
	
	ld->addr = addr;
	ld->size = 0;
	ld->mode = mode;


	if (info)
	{
		ld->info = new char[strlen(info)+1];
		strcpy(ld->info, info);
	}

	if (note)
	{
		ld->note = new char[strlen(note) + 1];
		strcpy(ld->note, note);
	}

	if (ld->mode & LOG_TITLE)
	{
		_curTitle = (log_data*)Addsorteddata(&(_logTable.data), ld);
		delete ld;
	}
	else if (_curTitle)
	{
		if (!_curTitle->subDataTail)
		{
			_curTitle->subDataHeadler = ld;
			_curTitle->subDataTail = ld;
		}
		else
		{
			_curTitle->subDataTail->nextData = ld;
			_curTitle->subDataTail = ld;
		}

		if (_curTitle->mode & LOG_TITLE_SPREAD)
		{
			Addsorteddata(&(_logTable.data), ld);
		}
		else if (ld->mode & LOG_TITLE_END)
		{
			_curTitle = NULL;
		}
		ld->mode = LOG_TITLE_SUB;
	}
	else
	{
		Addsorteddata(&(_logTable.data), ld);
		delete ld;
	}
	if (_logTable.hw != NULL)
		InvalidateRect(_logTable.hw, NULL, FALSE);
}

void LogWindow::ShowLogWindow()
{
	Quicktablewindow(&_logTable, 15, 3, LogWindowWinclass, _logWindowName);
}


char* LogWindow::LogSprintfI(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	_vsnprintf(_logSprintfBufI, TEXTLEN - 1, format, args);
	va_end(args);
	return _logSprintfBufI;
}

char* LogWindow::LogSprintfN(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	_vsnprintf(_logSprintfBufN, TEXTLEN - 1, format, args);
	va_end(args);
	return _logSprintfBufN;
}

void LogWindow::Clear()
{
	Deletesorteddatarange(&(_logTable.data), 0, 0xFFFFFFFF);
	_titleIndex=0;
	_logIndex = 0;
}


HANDLE LogWindow::CreateLogFile(const char* filename)
{
	return CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
}

void LogWindow::LogToFile(HANDLE file, const char* format, ...)
{
	if (!file)
		return;
	char buffer[TEXTLEN];
	ulong buflen=0;
	va_list args;
	va_start(args, format);
	buflen=_vsnprintf(buffer, TEXTLEN - 1, format, args);
	va_end(args);
	strcat_s(buffer, "\r\n");
	WriteFile(file, buffer, buflen + 2, &buflen, NULL);

}

void LogWindow::CloseLogFile(HANDLE file)
{
	CloseHandle(file);
}