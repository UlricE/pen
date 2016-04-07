#include "diag.h"
#include "pen.h"
#include "windows.h"

int sigaction(int signum, const struct sigaction *act,
		struct sigaction *oldact)
{
	return 0;
}

uid_t getuid(void)
{
	return 0;
}


int inet_aton(const char *cp, struct in_addr *addr)
{
	addr->s_addr = inet_addr(cp);
	return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}


void make_nonblocking(int fd)
{
	int i;
	u_long mode = 1;
	if ((i = ioctlsocket(fd, FIONBIO, &mode)) != NO_ERROR)
		error("Can't ioctlsocket, error = %d", i);
}

static WSADATA wsaData;
static int ws_started = 0;

int start_winsock(void)
{
	int n;
	DEBUG(1, "start_winsock()");
	if (!ws_started) {
		n = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (n != NO_ERROR) {
			error("Error at WSAStartup() [%d]", WSAGetLastError());
		} else {
			DEBUG(2, "Winsock started");
			ws_started = 1;
		}
	}
	return ws_started;
}

void stop_winsock(void)
{
	WSACleanup();
	ws_started = 0;
}



static SERVICE_STATUS          ServiceStatus; 
static SERVICE_STATUS_HANDLE   ServiceStatusHandle; 

static VOID  WINAPI ServiceCtrlHandler (DWORD opcode); 
static VOID  WINAPI ServiceStart (DWORD argc, LPTSTR *argv); 
static DWORD ServiceInitialization (DWORD argc, LPTSTR *argv, DWORD *specificError); 

static void DeletePenService(SC_HANDLE schSCManager, char *service_name)
{
    	SC_HANDLE schService;

    	schService = OpenService(schSCManager, service_name, SERVICE_ALL_ACCESS);
    	if (schService == NULL) {
        	debug("Can't open service (%d)", (int)GetLastError());
        	return;
    	}
    	if (!DeleteService(schService)) {
        	debug("Can't delete service (%d)", (int)GetLastError());
    	}
    	CloseServiceHandle(schService);
}

int delete_service(char *service_name)
{
        SC_HANDLE schSCManager;

	debug("delete_service()", 0);

        // Open a handle to the SC Manager database.

        schSCManager = OpenSCManager(
            	NULL,                    // local machine
            	NULL,                    // ServicesActive database
            	SC_MANAGER_ALL_ACCESS);  // full access rights

        if (NULL == schSCManager) {
            	debug("OpenSCManager failed (%d)", (int)GetLastError());
	    	return 0;
	}

        DeletePenService(schSCManager, service_name);
	return 1;
}

static BOOL CreatePenService(SC_HANDLE schSCManager, char *service_name, char *display_name) 
{ 
    	TCHAR szPath[MAX_PATH]; 
    	SC_HANDLE schService;
    
    	if( !GetModuleFileName( NULL, szPath, MAX_PATH ) ) {
        	debug("GetModuleFileName failed (%d)", (int)GetLastError()); 
        	return FALSE;
    	}

    	schService = CreateService( 
        	schSCManager,              // SCManager database 
        	service_name,              // name of service 
        	display_name,              // service name to display 
        	SERVICE_ALL_ACCESS,        // desired access 
        	SERVICE_WIN32_OWN_PROCESS, // service type 
        	SERVICE_AUTO_START,      // start type 
        	SERVICE_ERROR_NORMAL,      // error control type 
        	szPath,                    // path to service's binary 
        	NULL,                      // no load ordering group 
        	NULL,                      // no tag identifier 
        	NULL,                      // no dependencies 
        	NULL,                      // LocalSystem account 
        	NULL);                     // no password 
 
    	if (schService == NULL) {
        	debug("CreateService failed (%d)", (int)GetLastError()); 
        	return FALSE;
    	} else {
        	CloseServiceHandle(schService); 
        	return TRUE;
    	}
}

int install_service(char *service_name)
{
	SC_HANDLE schSCManager;

	// Open a handle to the SC Manager database. 
 
	debug("install_service()", 0);

	schSCManager = OpenSCManager( 
	    	NULL,                    // local machine 
	    	NULL,                    // ServicesActive database 
	    	SC_MANAGER_ALL_ACCESS);  // full access rights 
 
	if (NULL == schSCManager) 
	    	debug("OpenSCManager failed (%d)", (int)GetLastError());

	if (CreatePenService(schSCManager, service_name, service_name)) {
		debug("Success");
	} else {
		debug("Failure");
	}
	return 0;
}

int service_main(int argc, char **argv) 
{ 
   	SERVICE_TABLE_ENTRY   DispatchTable[] = { 
/* http://msdn.microsoft.com/en-us/library/ms686001(VS.85).aspx
   If the service is installed with the SERVICE_WIN32_OWN_PROCESS service type,
   this member is ignored, but cannot be NULL.
   This member can be an empty string ("").
*/
      		{ /*SERVICE_NAME*/"", ServiceStart      }, 
      		{ NULL,              NULL          } 
   	}; 

   	debug("service_main(%d, %p)", argc, argv);

   	if (!StartServiceCtrlDispatcher( DispatchTable)) { 
      		debug(" [PEN] StartServiceCtrlDispatcher (%d)\n", 
         	GetLastError()); 
   	} 
   	return 0;
} 
 
static void WINAPI ServiceStart (DWORD argc, LPTSTR *argv) 
{ 
    	DWORD status; 
    	DWORD specificError; 
 
    	debug("ServiceStart()");
    	ServiceStatus.dwServiceType        = SERVICE_WIN32; 
    	ServiceStatus.dwCurrentState       = SERVICE_START_PENDING; 
    	ServiceStatus.dwControlsAccepted   =
			SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE; 
    	ServiceStatus.dwWin32ExitCode      = 0; 
    	ServiceStatus.dwServiceSpecificExitCode = 0; 
    	ServiceStatus.dwCheckPoint         = 0; 
    	ServiceStatus.dwWaitHint           = 0; 
	 
    	ServiceStatusHandle = RegisterServiceCtrlHandler( 
/* http://msdn.microsoft.com/en-us/library/ms685054(VS.85).aspx
   If the service type is SERVICE_WIN32_OWN_PROCESS, the function does not
   verify that the specified name is valid, because there is only one
   registered service in the process. */
        	"",  // SERVICE_NAME
        	ServiceCtrlHandler); 
 
    	if (ServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) { 
        	debug(" [PEN] RegisterServiceCtrlHandler failed %d\n", GetLastError()); 
        	return; 
    	} 
 
    	// Initialization code goes here. 
    	status = ServiceInitialization(argc,argv, &specificError); 
 
    	// Handle error condition 
    	if (status != NO_ERROR) { 
        	ServiceStatus.dwCurrentState       = SERVICE_STOPPED; 
        	ServiceStatus.dwCheckPoint         = 0; 
        	ServiceStatus.dwWaitHint           = 0; 
        	ServiceStatus.dwWin32ExitCode      = status; 
        	ServiceStatus.dwServiceSpecificExitCode = specificError; 
	 
        	SetServiceStatus (ServiceStatusHandle, &ServiceStatus); 
        	return; 
    	} 
 
    	// Initialization complete - report running status. 
    	ServiceStatus.dwCurrentState       = SERVICE_RUNNING; 
    	ServiceStatus.dwCheckPoint         = 0; 
    	ServiceStatus.dwWaitHint           = 0; 
 
    	if (!SetServiceStatus (ServiceStatusHandle, &ServiceStatus)) { 
        	status = GetLastError(); 
        	debug(" [PEN] SetServiceStatus error %ld\n",status); 
    	} 
 
    	// This is where the service does its work. 
    	debug(" [PEN] Returning the Main Thread \n",0); 
    	mainloop();
 
    	return; 
}
 
// Stub initialization function. 
static DWORD ServiceInitialization(DWORD   argc, LPTSTR  *argv, DWORD *specificError) 
{ 
    	return(0); 
}


static VOID WINAPI ServiceCtrlHandler (DWORD Opcode) 
{ 
   	DWORD status; 
 
   	switch(Opcode) { 
      	case SERVICE_CONTROL_PAUSE: 
      	// Do whatever it takes to pause here. 
         	ServiceStatus.dwCurrentState = SERVICE_PAUSED; 
         	break; 
 
      	case SERVICE_CONTROL_CONTINUE: 
      	// Do whatever it takes to continue here. 
         	ServiceStatus.dwCurrentState = SERVICE_RUNNING; 
         	break; 
 
      	case SERVICE_CONTROL_STOP: 
      	// Do whatever it takes to stop here. 
	 	stop_winsock();
         	ServiceStatus.dwWin32ExitCode = 0; 
         	ServiceStatus.dwCurrentState  = SERVICE_STOPPED; 
         	ServiceStatus.dwCheckPoint    = 0; 
         	ServiceStatus.dwWaitHint      = 0; 

         	if (!SetServiceStatus (ServiceStatusHandle, &ServiceStatus)) { 
            		status = GetLastError(); 
            		debug(" [PEN] SetServiceStatus error %ld\n", status); 
         	} 
 
         	debug(" [PEN] Leaving Service \n",0); 
         	return; 
 
      	case SERVICE_CONTROL_INTERROGATE: 
      	// Fall through to send current status. 
         	break; 
 
      	default: 
         	debug(" [PEN] Unrecognized opcode %ld\n", Opcode); 
   	} 
 
   	// Send current status. 
   	if (!SetServiceStatus (ServiceStatusHandle,  &ServiceStatus)) { 
      		status = GetLastError(); 
      		debug(" [PEN] SetServiceStatus error %ld\n", status); 
   	} 
   	return; 
}

