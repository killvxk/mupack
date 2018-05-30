
#include "stdafx.h"
#include "main.h"
#include "About.h"
//--------------------------------------------
#pragma comment(linker,"/MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR")
#pragma pack(1)
//--------------------------------------------
#ifdef AP_UNIX_STYLE
   #include <unistd.h>
   #define CB_CALLCONV
#else
   #include <io.h>
   #define AP_HAS_CONIO
   #ifdef AP_DLL
      #define CB_CALLCONV __stdcall
   #else
      #define CB_CALLCONV __cdecl
   #endif
#endif
//--------------------------------------------
// Global Variables:
//--------------------------------------------
HINSTANCE hInst;	// current instance
static HDROP	hDrop;
static HICON	hIcon;
static HBITMAP	hBitmap;
static HWND	hButton;
//--------------------------------------------
static HWND	hwndMain;		// main application window 
static HMENU	hSysMenu;

//--------------------------------------------
static HACCEL	hAccel;
//--------------------------------------------
static char cFname[256];
static char cFnameOpen[256];
static char cFnameSave[256];
//--------------------------------------------
static OPENFILENAME openfn;
static OPENFILENAME savefn;
static DWORD nFilterIndex=1;
static char szCurDir[]=".";
static char szFilterOpn[]=TEXT("Executable files (*.exe)\0*.exe\0Dynamic Link Libraries (*.dll)\0*.dll\0OLE-ActiveX Controls (*.ocx)\0*.ocx\0Screen Savers (*.scr)\0*.scr\0All files (*.*)\0*.*\0\0");
static char szFilterSave[]=TEXT("All files (*.*)\0*.*\0\0");
static char* szAbout = "About...";
//--------------------------------------------
static BOOL			bFileOpen=FALSE;
//--------------------------------------------
// Forward declarations of functions included in this code module:
//--------------------------------------------
static LRESULT DlgProc(HWND hDlg,UINT uMsg,WPARAM wParam,LPARAM lParam);
//--------------------------------------------
static BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam);
static void OnCommand (HWND hwnd, int id, HWND hwndCtl, UINT codeNotify);
static void OnSysCommand(HWND hwnd, UINT cmd, int x, int y);
static void OnDropFiles(HWND hwnd, HDROP hDrop);
static void OnPaint (HWND hwnd);
static void OnDestroy (HWND hwnd);
static void OnClose(HWND hwnd);
//--------------------------------------------
static void EnableItems(HWND hwnd);
static int CB_CALLCONV callback(unsigned int inpos, unsigned int outpos);
//--------------------------------------------
/****************************************************************************
*								WinMain
****************************************************************************/
int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	MSG msg;
	hInst=GetModuleHandle(0);
	DialogBoxParam(hInst,MAKEINTRESOURCE(IDD_MAINDLG),0,(DLGPROC)DlgProc,0);
	ExitProcess(0);
	return (int) msg.wParam;
}

/****************************************************************************
*						DlgProc(HWND, unsigned, WORD, LONG)
*
*  PURPOSE:  Processes messages for the main window.
*
*  WM_INITDIALOG	- initialize the application
*  WM_COMMAND		- process the application
*  WM_SYSCOMMAND	- process the system menu
*  WM_PAINT			- Paint the main window
*  WM_DESTROY		- post a quit message and return
*  WM_CLOSE			- process close event
*  WM_DROPFILES		- for drop file into the application
*
****************************************************************************/
static LRESULT DlgProc(HWND hDlg,UINT uiMsg,WPARAM wParam,LPARAM lParam)
{
	switch (uiMsg) 
	{
	HANDLE_MSG(hDlg, WM_INITDIALOG,	OnInitDialog);
	HANDLE_MSG(hDlg, WM_COMMAND,	OnCommand);
	HANDLE_MSG(hDlg, WM_SYSCOMMAND,	OnSysCommand);
	HANDLE_MSG(hDlg, WM_PAINT,		OnPaint);
	HANDLE_MSG(hDlg, WM_DESTROY,	OnDestroy);
	HANDLE_MSG(hDlg, WM_CLOSE,		OnClose);
	HANDLE_MSG(hDlg, WM_DROPFILES,	OnDropFiles);
	}
	return 0;
}
/****************************************************************************
*								OnInitDialog
****************************************************************************/
static BOOL OnInitDialog(HWND hwnd, HWND hwndFocus, LPARAM lParam)
{
	hwndMain=hwnd;
	hIcon=LoadIcon(hInst,MAKEINTRESOURCE(IDI_ICON));
	SendMessage(hwnd,WM_SETICON,TRUE,(WPARAM)hIcon);
	DragAcceptFiles(hwnd,TRUE);
	hSysMenu = GetSystemMenu(hwnd,FALSE);
	if (hSysMenu != NULL)
	{
		AppendMenu(hSysMenu,MF_SEPARATOR,0,0);
		AppendMenu(hSysMenu,MF_STRING | MF_ENABLED,
				ID_ABOUT,szAbout);
	}
	return FALSE;
}
/****************************************************************************
*								OnCommand
*
*  hwnd			Handle of window to which this message applies
*  id			Specifies the identifier of the menu item, 
*				control, or accelerator.
*  hwndCtl		Handle of the control sending the message if the message
*				is from a control, otherwise, this parameter is NULL. 
*  codeNotify	Specifies the notification code if the message is from 
*				a control.
*				This parameter is 1 when the message is from an 
*				accelerator.
*				This parameter is 0 when the message is from a menu.
****************************************************************************/
static void OnCommand (HWND hwnd, int id, HWND hwndCtl, UINT codeNotify)
{
	switch (id) 
	{	/* id */
		case IDCLOSE:
			SendMessage(hwnd,WM_CLOSE,NULL,NULL);
			break;
              	                  
		case IDOK:
			EndDialog(hwnd,0);
			break;
		case IDC_ABOUT:
			DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hwnd, (DLGPROC)About);
			break;     
		case ID_FILE_OPEN:
			// get a file path
 			cFname[0]=0x00;
			ZeroMemory(&openfn, sizeof(openfn));
			openfn.hwndOwner=GetActiveWindow();
			openfn.lpstrFile=cFname;
			openfn.nMaxFile=sizeof(cFname);
			openfn.lStructSize=sizeof(openfn);
			openfn.lpstrFilter=szFilterOpn; 
			openfn.nFilterIndex=nFilterIndex;
			//openfn.lpstrInitialDir=szCurDir;
			openfn.Flags=OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_LONGNAMES | OFN_HIDEREADONLY;
			if(!GetOpenFileName(&openfn))
			{
				return;
			}
			strcpy(cFnameOpen,cFname);
			strcpy(cFnameSave,cFnameOpen);
			SetDlgItemText(hwnd,IDC_FILE_OPEN,cFnameOpen);
			EnableItems(hwnd);
			if(cFnameOpen[0]==0x00) return;
			bFileOpen=TRUE;
			break;
		case ID_FILE_PROTECT:
			SendDlgItemMessage(hwnd,IDC_PROGRESS1,PBM_SETSTEP,1,0);
			SendDlgItemMessage(hwnd,IDC_PROGRESS1,PBM_SETPOS,0,0);
			CryptFile(callback,cFnameOpen);
			break;
	}/* id */
}

/****************************************************************************
*								OnSysCommand
****************************************************************************/
static void OnSysCommand(HWND hwnd,UINT cmd, int x, int y)
{
	switch (cmd) 
	{	/* id */
		case ID_ABOUT:
			DialogBox(hInst, (LPCTSTR)IDD_ABOUTBOX, hwnd, (DLGPROC)About);
			break;     
	}/* id */
}

/****************************************************************************
*								OnPaint
*
*  hwnd            Handle of window to which this message applies
*
*  hdrop           Handle of drop
*
****************************************************************************/
static void OnDropFiles(HWND hwnd, HDROP hDrop)
{
	DragQueryFile(hDrop,0,cFnameOpen,sizeof(cFnameOpen));
	DragFinish(hDrop);
	SetDlgItemText(hwnd,IDC_FILE_OPEN,cFnameOpen);
	EnableItems(hwnd);
	if(cFnameOpen[0]==0x00) return;
	bFileOpen=TRUE;
	strcpy(cFnameSave,cFnameOpen);
	SetDlgItemText(hwnd,IDC_FILE_OPEN,cFnameOpen);
}

/****************************************************************************
*								OnPaint
*
*  hwnd            Handle of window to which this message applies
*
*  PURPOSE:        Windows calls this handler when the window needs 
*			       repainting.
****************************************************************************/
static void OnPaint (HWND hwnd)
{
    HDC         hdc ;
    PAINTSTRUCT ps ;

	hdc = BeginPaint(hwnd, &ps);
	// TODO: Add any drawing code here...
	EndPaint(hwnd, &ps);
}

/****************************************************************************
*								OnDestroy
*
*  hwnd            Handle of window to which this message applies
*
*  PURPOSE:        Notification that the specified window is being destroyed.
*                  The window is no longer visible to the user.
****************************************************************************/
static void OnDestroy (HWND hwnd)
{
	PostQuitMessage(0);;
}

/****************************************************************************
*								OnClose
*
*  hwnd            Handle of window to which this message applies
*
*  PURPOSE:        Notification that the specified window is being closed.
*
****************************************************************************/
static void OnClose(HWND hwnd)
{
	EndDialog(hwnd,0);
}
//***************************************************************************
static void EnableItems(HWND hwnd)
{
	hButton=GetDlgItem(hwnd,ID_FILE_SAVE); 
	EnableWindow(hButton,TRUE);
	hButton=GetDlgItem(hwnd,ID_FILE_PROTECT); 
	EnableWindow(hButton,TRUE);
	hButton=GetDlgItem(hwnd,ID_DEPACK);
	EnableWindow(hButton,TRUE);
}
//***************************************************************************
static int CB_CALLCONV callback(unsigned int inpos, unsigned int outpos)
{
   SendDlgItemMessage(hwndMain,IDC_PROGRESS1,PBM_SETPOS,inpos,0);
   return (1); // continue packing
}
