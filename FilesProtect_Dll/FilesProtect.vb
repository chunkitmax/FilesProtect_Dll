Imports System.Runtime.InteropServices

Public Class FileProtect

    Private Enum EMoveMethod : uint
        FILE_BEGIN = 0
        FILE_CURRENT = 1
        FILE_END = 2
    End Enum

    <DllImport("kernel32.dll", SetLastError:=True)> _
    Private Shared Function SetFilePointer( _
        ByVal hFile As IntPtr, _
        ByVal lDistanceToMove As Integer, _
        ByRef lpDistanceToMoveHigh As IntPtr, _
        ByVal dwMoveMethod As EMoveMethod) _
        As System.UInt32
    End Function

    <DllImport("kernel32.dll", SetlastError:=True)> _
    Private Shared Function ReadFile(ByVal hFile As IntPtr, ByVal Buffer As IntPtr, _
    ByVal nNumberOfBytesToRead As Integer, ByRef lpNumberOfBytesRead As Integer, _
    ByRef lpOverlapped As System.Threading.NativeOverlapped) As Integer
    End Function

    <DllImport("advapi32.dll", CharSet:=CharSet.Auto, SetLastError:=True)> _
    Private Shared Function OpenSCManager(ByVal machineName As String, ByVal databaseName As String, ByVal desiredAccess As ACCESS_MASK) As IntPtr
    End Function
    <DllImport("advapi32.dll", SetLastError:=True)> _
    Private Shared Function CloseServiceHandle(ByVal serviceHandle As IntPtr) As Boolean
    End Function
    <Flags()> _
    Private Enum ACCESS_MASK As Int32

        ''' <summary>
        ''' Required to connect to the service control manager.
        ''' </summary>
        SC_MANAGER_CONNECT = &H1

        ''' <summary>
        ''' Required to call the CreateService function to create a service
        ''' object and add it to the database.
        ''' </summary>
        SC_MANAGER_CREATE_SERVICE = &H2

        ''' <summary>
        ''' Required to call the EnumServicesStatusEx function to list the
        ''' services that are in the database.
        ''' </summary>
        SC_MANAGER_ENUMERATE_SERVICE = &H4

        ''' <summary>
        ''' Required to call the LockServiceDatabase function to acquire a
        ''' lock on the database.
        ''' </summary>
        SC_MANAGER_LOCK = &H8

        ''' <summary>
        ''' Required to call the QueryServiceLockStatus function to retrieve
        ''' the lock status information for the database.
        ''' </summary>
        SC_MANAGER_QUERY_LOCK_STATUS = &H10

        ''' <summary>
        ''' Required to call the NotifyBootConfigStatus function.
        ''' </summary>
        SC_MANAGER_MODIFY_BOOT_CONFIG = &H20

        ''' <summary>
        ''' Includes STANDARD_RIGHTS_REQUIRED, in addition to all access
        ''' rights in this table.
        ''' </summary>
        SC_MANAGER_ALL_ACCESS = EFileAccess.STANDARD_RIGHTS_REQUIRED Or _
        SC_MANAGER_CONNECT Or _
        SC_MANAGER_CREATE_SERVICE Or _
        SC_MANAGER_ENUMERATE_SERVICE Or _
        SC_MANAGER_LOCK Or _
        SC_MANAGER_QUERY_LOCK_STATUS Or _
        SC_MANAGER_MODIFY_BOOT_CONFIG

        GENERIC_READ = EFileAccess.STANDARD_RIGHTS_READ Or _
        SC_MANAGER_ENUMERATE_SERVICE Or _
        SC_MANAGER_QUERY_LOCK_STATUS

        GENERIC_WRITE = EFileAccess.STANDARD_RIGHTS_WRITE Or _
        SC_MANAGER_CREATE_SERVICE Or _
        SC_MANAGER_MODIFY_BOOT_CONFIG

        GENERIC_EXECUTE = EFileAccess.STANDARD_RIGHTS_EXECUTE Or _
        SC_MANAGER_CONNECT Or SC_MANAGER_LOCK

        GENERIC_ALL = SC_MANAGER_ALL_ACCESS

    End Enum
    <DllImport("advapi32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function OpenService(ByVal hSCManager As IntPtr, ByVal lpServiceName As String, ByVal dwDesiredAccess As SERVICE_ACCESS) As IntPtr
    End Function
    Private Enum SERVICE_ACCESS As Integer

        STANDARD_RIGHTS_REQUIRED = &HF0000
        SERVICE_QUERY_CONFIG = &H1
        SERVICE_CHANGE_CONFIG = &H2
        SERVICE_QUERY_STATUS = &H4
        SERVICE_ENUMERATE_DEPENDENTS = &H8
        SERVICE_START = &H10
        SERVICE_STOP = &H20
        SERVICE_PAUSE_CONTINUE = &H40
        SERVICE_INTERROGATE = &H80
        SERVICE_USER_DEFINED_CONTROL = &H100
        SERVICE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED Or _
                SERVICE_QUERY_CONFIG Or _
                SERVICE_CHANGE_CONFIG Or _
                SERVICE_QUERY_STATUS Or _
                SERVICE_ENUMERATE_DEPENDENTS Or _
                SERVICE_START Or SERVICE_STOP Or _
                SERVICE_PAUSE_CONTINUE Or _
                SERVICE_INTERROGATE Or _
                SERVICE_USER_DEFINED_CONTROL

    End Enum
    <DllImport("advapi32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function CreateService(ByVal hSCManager As IntPtr, ByVal serviceName As String, _
                ByVal displayName As String, ByVal desiredAccess As SERVICE_ACCESS, ByVal serviceType As SERVICE_TYPE, _
                ByVal startType As SERVICE_START, ByVal errorcontrol As SERVICE_ERROR, ByVal binaryPathName As String, _
                ByVal loadOrderGroup As String, ByVal TagBY As Int32, ByVal dependencides As String, _
                ByVal serviceStartName As String, ByVal password As String) As IntPtr
    End Function
    Private Enum SERVICE_ERROR
        ''' <summary>
        ''' The startup program ignores the error and continues the startup
        ''' operation.
        ''' </summary>
        SERVICE_ERROR_IGNORE = 0

        ''' <summary>
        ''' The startup program logs the error in the event log but continues
        ''' the startup operation.
        ''' </summary>
        SERVICE_ERROR_NORMAL = 1

        ''' <summary>
        ''' The startup program logs the error in the event log. If the 
        ''' last-known-good configuration is being started, the startup 
        ''' operation continues. Otherwise, the system is restarted with 
        ''' the last-known-good configuration.
        ''' </summary>
        SERVICE_ERROR_SEVERE = 2

        ''' <summary>
        ''' The startup program logs the error in the event log, if possible.
        ''' If the last-known-good configuration is being started, the startup
        ''' operation fails. Otherwise, the system is restarted with the 
        ''' last-known good configuration.
        ''' </summary>
        SERVICE_ERROR_CRITICAL = 3

    End Enum

    ''' <summary>
    ''' Service types.
    ''' </summary>
    <Flags()> _
    Private Enum SERVICE_TYPE As UInteger
        ''' <summary>
        ''' Driver service.
        ''' </summary>
        SERVICE_KERNEL_DRIVER = &H1

        ''' <summary>
        ''' File system driver service.
        ''' </summary>
        SERVICE_FILE_SYSTEM_DRIVER = &H2

        ''' <summary>
        ''' Service that runs in its own process.
        ''' </summary>
        SERVICE_WIN32_OWN_PROCESS = &H10

        ''' <summary>
        ''' Service that shares a process with one or more other services.
        ''' </summary>
        SERVICE_WIN32_SHARE_PROCESS = &H20

        ''' <summary>
        ''' The service can interact with the desktop.
        ''' </summary>
        SERVICE_INTERACTIVE_PROCESS = &H100
    End Enum
    <DllImport("advapi32.dll", SetLastError:=True, CharSet:=CharSet.Auto)> _
    Private Shared Function StartService(ByVal hService As IntPtr, ByVal dwNumServiceArgs As Integer, ByVal lpServiceArgVectors As String) As Boolean
    End Function

    ''' <summary>
    ''' Service start options 
    ''' </summary>
    Private Enum SERVICE_START As UInteger
        ''' <summary>
        ''' A device driver started by the system loader. This value is valid
        ''' only for driver services.
        ''' </summary>
        SERVICE_BOOT_START = &H0

        ''' <summary>
        ''' A device driver started by the IoInitSystem function. This value 
        ''' is valid only for driver services.
        ''' </summary>
        SERVICE_SYSTEM_START = &H1

        ''' <summary>
        ''' A service started automatically by the service control manager 
        ''' during system startup. For more information, see Automatically 
        ''' Starting Services.
        ''' </summary>     
        SERVICE_AUTO_START = &H2

        ''' <summary>
        ''' A service started by the service control manager when a process 
        ''' calls the StartService function. For more information, see 
        ''' Starting Services on Demand.
        ''' </summary>
        SERVICE_DEMAND_START = &H3

        ''' <summary>
        ''' A service that cannot be started. Attempts to start the service
        ''' result in the error code ERROR_SERVICE_DISABLED.
        ''' </summary>
        SERVICE_DISABLED = &H4
    End Enum
    <DllImport("advapi32.dll", SetLastError:=True)> _
    Private Shared Function ControlService(ByVal hService As IntPtr, ByVal dwControl As SERVICE_CONTROL, ByRef lpServiceStatus As SERVICE_STATUS) As Boolean
    End Function
    Private Enum SERVICE_CONTROL As Integer
        [STOP] = &H1
        PAUSE = &H2
        LPCONTINUE = &H3
        INTERROGATE = &H4
        SHUTDOWN = &H5
        PARAMCHANGE = &H6
        NETBINDADD = &H7
        NETBINDREMOVE = &H8
        NETBINDENABLE = &H9
        NETBINDDISABLE = &HA
        DEVICEEVENT = &HB
        HARDWAREPROFILECHANGE = &HC
        POWEREVENT = &HD
        SESSIONCHANGE = &HE
    End Enum
    Private Structure SERVICE_STATUS
        Dim dwServiceType As Int32
        Dim dwCurrentState As Int32
        Dim dwControlsAccepted As Int32
        Dim dwWin32ExitCode As Int32
        Dim dwServiceSpecificExitCode As Int32
        Dim dwCheckPoint As Int32
        Dim dwWaitHint As Int32
    End Structure
    Private Enum SERVICE_STATE As Integer

        SERVICE_STOPPED = &H1
        SERVICE_START_PENDING = &H2
        SERVICE_STOP_PENDING = &H3
        SERVICE_RUNNING = &H4
        SERVICE_CONTINUE_PENDING = &H5
        SERVICE_PAUSE_PENDING = &H6
        SERVICE_PAUSED = &H7
    End Enum
    <Runtime.InteropServices.DllImport("advapi32.dll", SetLastError:=True)> _
    Private Shared Function DeleteService(ByVal hService As IntPtr) As Boolean
    End Function

    Private Enum SERVICE_ACCEPT As Integer

        [STOP] = &H1
        PAUSE_CONTINUE = &H2
        SHUTDOWN = &H4
        PARAMCHANGE = &H8
        NETBINDCHANGE = &H10
        HARDWAREPROFILECHANGE = &H20
        POWEREVENT = &H40
        SESSIONCHANGE = &H80
    End Enum
    <Runtime.InteropServices.DllImport("kernel32.dll", SetLastError:=True)> _
    Private Shared Function CloseHandle(ByVal hObject As IntPtr) As <Runtime.InteropServices.MarshalAs(Runtime.InteropServices.UnmanagedType.Bool)> Boolean
    End Function
    <Runtime.InteropServices.DllImport("kernel32.dll", ExactSpelling:=True, SetLastError:=True, CharSet:=Runtime.InteropServices.CharSet.Auto)> _
    Private Shared Function DeviceIoControl(ByVal hDevice As IntPtr, _
     ByVal dwIoControlCode As Integer, ByVal lpInBuffer As IntPtr, _
         ByVal nInBufferSize As Integer, ByVal lpOutBuffer As IntPtr, _
         ByVal nOutBufferSize As Integer, ByRef lpBytesReturned As Integer, _
         ByVal lpOverlapped As IntPtr) As Integer
    End Function

    <System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError:=True, CharSet:=System.Runtime.InteropServices.CharSet.Auto)> _
    Private Shared Function CreateFile(ByVal lpFileName As String, _
    ByVal dwDesiredAccess As EFileAccess, _
    ByVal dwShareMode As EFileShare, _
    ByVal lpSecurityAttributes As IntPtr, _
    ByVal dwCreationDisposition As ECreationDisposition, _
    ByVal dwFlagsAndAttributes As EFileAttributes, _
    ByVal hTemplateFile As IntPtr) As IntPtr
    End Function

    Private Enum EFileAccess As System.Int32
        DELETE = &H10000
        READ_CONTROL = &H20000
        WRITE_DAC = &H40000
        WRITE_OWNER = &H80000
        SYNCHRONIZE = &H100000
        STANDARD_RIGHTS_REQUIRED = &HF0000
        STANDARD_RIGHTS_READ = READ_CONTROL
        STANDARD_RIGHTS_WRITE = READ_CONTROL
        STANDARD_RIGHTS_EXECUTE = READ_CONTROL
        STANDARD_RIGHTS_ALL = &H1F0000
        SPECIFIC_RIGHTS_ALL = &HFFFF
        ACCESS_SYSTEM_SECURITY = &H1000000
        MAXIMUM_ALLOWED = &H2000000
        GENERIC_READ = &H80000000
        GENERIC_WRITE = &H40000000
        GENERIC_EXECUTE = &H20000000
        GENERIC_ALL = &H10000000
    End Enum
    Private Enum EFileShare
        FILE_SHARE_NONE = &H0
        FILE_SHARE_READ = &H1
        FILE_SHARE_WRITE = &H2
        FILE_SHARE_DELETE = &H4
    End Enum
    Private Enum ECreationDisposition
        ''' <summary>
        ''' Creates a new file, only if it does not already exist.
        ''' If the specified file exists, the function fails and the last-error code is set to ERROR_FILE_EXISTS (80).
        ''' If the specified file does not exist and is a valid path to a writable location, a new file is created.
        ''' </summary>
        CREATE_NEW = 1

        ''' <summary>
        ''' Creates a new file, always.
        ''' If the specified file exists and is writable, the function overwrites the file, the function succeeds, and last-error code is set to ERROR_ALREADY_EXISTS (183).
        ''' If the specified file does not exist and is a valid path, a new file is created, the function succeeds, and the last-error code is set to zero.
        ''' For more information, see the Remarks section of this topic.
        ''' </summary>
        CREATE_ALWAYS = 2

        ''' <summary>
        ''' Opens a file or device, only if it exists.
        ''' If the specified file or device does not exist, the function fails and the last-error code is set to ERROR_FILE_NOT_FOUND (2).
        ''' For more information about devices, see the Remarks section.
        ''' </summary>
        OPEN_EXISTING = 3

        ''' <summary>
        ''' Opens a file, always.
        ''' If the specified file exists, the function succeeds and the last-error code is set to ERROR_ALREADY_EXISTS (183).
        ''' If the specified file does not exist and is a valid path to a writable location, the function creates a file and the last-error code is set to zero.
        ''' </summary>
        OPEN_ALWAYS = 4

        ''' <summary>
        ''' Opens a file and truncates it so that its size is zero bytes, only if it exists.
        ''' If the specified file does not exist, the function fails and the last-error code is set to ERROR_FILE_NOT_FOUND (2).
        ''' The calling process must open the file with the GENERIC_WRITE bit set as part of the dwDesiredAccess parameter.
        ''' </summary>
        TRUNCATE_EXISTING = 5
    End Enum
    Private Enum EFileAttributes
        FILE_ATTRIBUTE_READONLY = &H1
        FILE_ATTRIBUTE_HIDDEN = &H2
        FILE_ATTRIBUTE_SYSTEM = &H4
        FILE_ATTRIBUTE_DIRECTORY = &H10
        FILE_ATTRIBUTE_ARCHIVE = &H20
        FILE_ATTRIBUTE_DEVICE = &H40
        FILE_ATTRIBUTE_NORMAL = &H80
        FILE_ATTRIBUTE_TEMPORARY = &H100
        FILE_ATTRIBUTE_SPARSE_FILE = &H200
        FILE_ATTRIBUTE_REPARSE_POINT = &H400
        FILE_ATTRIBUTE_COMPRESSED = &H800
        FILE_ATTRIBUTE_OFFLINE = &H1000
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = &H2000
        FILE_ATTRIBUTE_ENCRYPTED = &H4000
        FILE_ATTRIBUTE_VIRTUAL = &H10000

        'This parameter can also contain combinations of flags (FILE_FLAG_*) 
        FILE_FLAG_BACKUP_SEMANTICS = &H2000000
        FILE_FLAG_DELETE_ON_CLOSE = &H4000000
        FILE_FLAG_NO_BUFFERING = &H2000000
        FILE_FLAG_OPEN_NO_RECALL = &H100000
        FILE_FLAG_OPEN_REPARSE_POINT = &H200000
        FILE_FLAG_OVERLAPPED = &H40000000
        FILE_FLAG_POSIX_SEMANTICS = &H100000
        FILE_FLAG_RANDOM_ACCESS = &H10000000
        FILE_FLAG_SEQUENTIAL_SCAN = &H8000000
        FILE_FLAG_WRITE_THROUGH = &H80000000
    End Enum

    Const NEW_TARGET_FILE = &H223800
    Const SET_LAST_TARGET_FILE_NAME = &H223804
    Const SET_LAST_TARGET_FILE_DEVICE_NAME = &H223808
    Const DEL_TARGET_FILE_BY_FILE_NAME = &H22380C
    Const DEL_TARGET_FILE_BY_FILE_DEVICE_NAME = &H223810

    Const NEW_LOCK_FILE = &H223814
    Const SET_LAST_LOCK_FILE_FULL_PATH = &H223818
    Const DEL_LOCK_FILE_BY_FILE_FULL_PATH = &H22381C

    Const NEW_DISABLE_FILE = &H223820
    Const SET_LAST_DISABLE_FILE_NAME = &H223824
    Const SET_LAST_DISABLE_FILE_DEVICE_NAME = &H223828
    Const DEL_DISABLE_FILE_BY_FILE_NAME = &H22382C
    Const DEL_DISABLE_FILE_BY_FILE_DEVICE_NAME = &H223830

    Const NEW_TARGET_DECUMENT = &H223834
    Const SET_LAST_TARGET_DOCUMENT_DEVICE_NAME = &H223838
    Const SET_LAST_TARGET_DOCUMENT_PATH = &H22383C
    Const DEL_TARGET_DOCUMENT_BY_PATH = &H223840

    Const NEW_LOCK_DOCUMENT = &H223844
    Const SET_LAST_LOCK_DOCUMENT_FULL_PATH = &H223848
    Const DEL_LOCK_DOCUMENT_BY_FULL_PATH = &H22384C

    Const NEW_DISABLE_DOCUMENT = &H223850
    Const SET_LAST_DISABLE_DOCUMENT_DEVICE_NAME = &H223854
    Const SET_LAST_DISABLE_DOCUMENT_PATH = &H223858
    Const DEL_DISABLE_DOCUMENT_BY_PATH = &H22385C

    Const SSDT_HOOK = &H223860
    Const SSDT_UNHOOK = &H223864
    Const SSDT_INIT = &H223868

    Const ERROR_SERVICE_ALREADY_RUNNING = &H420

    Public Overloads Shared Function SendToDriver(ByVal Msg As String, ByVal ControlCode As Integer) As Boolean
        Dim Handle As IntPtr = CreateFile("\\.\MyDriver", EFileAccess.GENERIC_READ Or EFileAccess.GENERIC_WRITE, EFileShare.FILE_SHARE_NONE, Nothing, ECreationDisposition.OPEN_EXISTING, EFileAttributes.FILE_ATTRIBUTE_NORMAL, Nothing)
        Dim BytesReturn As Integer
        'Dim TargetChar() As Char = New Char(9) {Chr(53), Chr(53), Chr(50), Chr(0), Chr(0), Chr(0), Chr(0), Chr(0), Chr(0), Chr(0)}
        'TargetChar = Target.ToString
        'ReDim Preserve TargetChar(9)
        Dim TargetChar() As Char = New Char() {}
        TargetChar = Msg.ToCharArray()
        ReDim Preserve TargetChar(Msg.Length - 1)
        Dim TargetByte As Byte() = New Byte(Msg.Length) {}
        For counter As Integer = 0 To Msg.Length - 1
            TargetByte(counter) = AscW(TargetChar(counter))
        Next
        TargetByte(Msg.Length) = AscW(Chr(0))
        Dim IntPointer As IntPtr = Marshal.AllocHGlobal(Msg.Length + 1)
        Marshal.Copy(TargetByte, 0, IntPointer, Msg.Length + 1)
        Dim a As Integer = DeviceIoControl(Handle, ControlCode, IntPointer, Msg.Length + 1, Nothing, 0, BytesReturn, Nothing)
        CloseHandle(Handle)
        Marshal.FreeHGlobal(IntPointer)
        If a Then Return True Else Return False
    End Function

    Public Overloads Shared Function SendToDriver(ByVal ControlCode As Integer) As Boolean
        Dim Handle As IntPtr = CreateFile("\\.\MyDriver", EFileAccess.GENERIC_READ Or EFileAccess.GENERIC_WRITE, EFileShare.FILE_SHARE_NONE, Nothing, ECreationDisposition.OPEN_EXISTING, EFileAttributes.FILE_ATTRIBUTE_NORMAL, Nothing)
        Dim BytesReturn As Integer
        Dim a As Integer = DeviceIoControl(Handle, ControlCode, Nothing, 0, Nothing, 0, BytesReturn, Nothing)
        CloseHandle(Handle)
        If a Then Return True Else Return False
    End Function

    Public Shared Function InstallSys(ByVal ServiceName As String, ByVal SysDisplayName As String, ByVal SysPath As String) As Boolean
        Dim hSCM As IntPtr = OpenSCManager(Nothing, Nothing, ACCESS_MASK.SC_MANAGER_ALL_ACCESS)
        Dim hService As IntPtr
        If hSCM = 0 Then
            MsgBox("InstallSys Failed!")
            Return False
        End If
        For counter As Integer = 0 To 2
            hService = CreateService(hSCM, ServiceName, SysDisplayName, SERVICE_ACCESS.SERVICE_ALL_ACCESS, SERVICE_TYPE.SERVICE_KERNEL_DRIVER, SERVICE_START.SERVICE_DEMAND_START, SERVICE_ERROR.SERVICE_ERROR_NORMAL, SysPath, Nothing, Nothing, Nothing, Nothing, Nothing)
            If hService <> 0 Then
                CloseServiceHandle(hService)
                Return True
            End If
        Next
        CloseServiceHandle(hSCM)
        'MsgBox("InstallSys Failed!")
        Return False
    End Function

    Public Shared Function UnInstallSys(ByVal ServiceName As String) As Boolean
        Dim hSCM As IntPtr = OpenSCManager(Nothing, Nothing, ACCESS_MASK.SC_MANAGER_ALL_ACCESS)
        If hSCM = 0 Then
            MsgBox("UnInstallSys Failed")
            Return False
        End If
        Dim hService As IntPtr = OpenService(hSCM, ServiceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS)
        If hService = 0 Then
            MsgBox("UnInstallSys Failed")
            Return False
        End If
        Dim rtstatus As Boolean = DeleteService(hService)
        CloseServiceHandle(hService)
        CloseServiceHandle(hSCM)
        Return True
    End Function

    Public Shared Function StartSys(ByVal ServiceName As String) As Boolean
        Dim hSCM As IntPtr = OpenSCManager(Nothing, Nothing, ACCESS_MASK.SC_MANAGER_ALL_ACCESS)
        If hSCM = 0 Then
            MsgBox("StartSys Failed")
            Return False
        End If
        Dim hService As IntPtr = OpenService(hSCM, ServiceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS)
        If hService = 0 Then
            MsgBox("StartSys Failed")
            Return False
        End If
        Dim rtstatus As Boolean = StartService(hService, Nothing, Nothing)
        CloseServiceHandle(hService)
        CloseServiceHandle(hSCM)
        If rtstatus = False Then
            If Runtime.InteropServices.Marshal.GetLastWin32Error = ERROR_SERVICE_ALREADY_RUNNING Then
                'MsgBox("Driver has already started!")
            Else
                MsgBox(ErrorToString(Runtime.InteropServices.Marshal.GetLastWin32Error))
            End If
            Return False
        Else
            Return True
        End If
    End Function

    Public Shared Function StopSys(ByVal ServiceName As String) As Boolean
        Dim hSCM As IntPtr = OpenSCManager(Nothing, Nothing, ACCESS_MASK.SC_MANAGER_ALL_ACCESS)
        If hSCM = 0 Then
            MsgBox("StopSys Failed")
            Return False
        End If
        Dim hService As IntPtr = OpenService(hSCM, ServiceName, SERVICE_ACCESS.SERVICE_ALL_ACCESS)
        If hService = 0 Then
            MsgBox("StopSys Failed")
            Return False
        End If
        Dim servicestatus As SERVICE_STATUS
        Dim rtstatus As Boolean = ControlService(hService, SERVICE_CONTROL.STOP, servicestatus)
        CloseServiceHandle(hService)
        CloseServiceHandle(hSCM)
        If rtstatus = False Then
            MsgBox("StopSys Failed (Cannot Stop)")
            Return False
        Else
            Return True
        End If
    End Function

    ''' <summary>
    ''' 增加文件到防刪列表
    ''' </summary>
    ''' <param name="磁碟機名稱">文件所在的磁碟機名稱連冒號 (e.g. "X:")</param>
    ''' <param name="文件路徑">文件所在位置的路徑 (e.g. "\xxx\xxx.txt")</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function 添加防刪文件(ByVal 磁碟機名稱 As String, ByVal 文件路徑 As String) As Boolean
        If Not SendToDriver(磁碟機名稱, SET_LAST_TARGET_FILE_DEVICE_NAME) Then Return False
        If Not SendToDriver(文件路徑, SET_LAST_TARGET_FILE_NAME) Then Return False
        Return SendToDriver(NEW_TARGET_FILE)
    End Function

    ''' <summary>
    ''' 增加文件到防讀列表
    ''' </summary>
    ''' <param name="文件完整路徑">文件所在位置的完整路徑 (e.g. "X:\xxx\xxx.txt")</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function 添加防讀文件(ByVal 文件完整路徑 As String) As Boolean
        If Not SendToDriver("\??\" & 文件完整路徑, SET_LAST_LOCK_FILE_FULL_PATH) Then Return False
        Return SendToDriver(NEW_LOCK_FILE)
    End Function

    ''' <summary>
    ''' 增加文件到防寫列表
    ''' </summary>
    ''' <param name="磁碟機名稱">文件所在的磁碟機名稱連冒號 (e.g. "X:")</param>
    ''' <param name="文件路徑">文件所在位置的路徑 (e.g. "\xxx\xxx.txt")</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function 添加防寫文件(ByVal 磁碟機名稱 As String, ByVal 文件路徑 As String) As Boolean
        If Not SendToDriver(磁碟機名稱, SET_LAST_DISABLE_FILE_DEVICE_NAME) Then Return False
        If Not SendToDriver(文件路徑, SET_LAST_DISABLE_FILE_NAME) Then Return False
        Return SendToDriver(NEW_DISABLE_FILE)
    End Function

    ''' <summary>
    ''' 增加資料夾到防刪列表
    ''' </summary>
    ''' <param name="磁碟機名稱">資料夾所在的磁碟機名稱連冒號 (e.g. "X:")</param>
    ''' <param name="資料夾路徑">資料夾所在位置的路徑 (e.g. "\xxx")</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function 添加防刪資料夾(ByVal 磁碟機名稱 As String, ByVal 資料夾路徑 As String) As Boolean
        If Not SendToDriver(磁碟機名稱, SET_LAST_TARGET_DOCUMENT_DEVICE_NAME) Then Return False
        If Not SendToDriver(資料夾路徑, SET_LAST_TARGET_DOCUMENT_PATH) Then Return False
        Return SendToDriver(NEW_TARGET_DECUMENT)
    End Function

    ''' <summary>
    ''' 增加資料夾到防讀列表
    ''' </summary>
    ''' <param name="資料夾完整路徑">資料夾所在位置的完整路徑 (e.g. "X:\xxx\xxx.txt")</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function 添加防讀資料夾(ByVal 資料夾完整路徑 As String) As Boolean
        If Not SendToDriver("\??\" & 資料夾完整路徑, SET_LAST_LOCK_DOCUMENT_FULL_PATH) Then Return False
        Return SendToDriver(NEW_LOCK_DOCUMENT)
    End Function

    ''' <summary>
    ''' 增加資料夾到防寫列表
    ''' </summary>
    ''' <param name="磁碟機名稱">資料夾所在的磁碟機名稱連冒號 (e.g. "X:")</param>
    ''' <param name="資料夾路徑">資料夾所在位置的路徑 (e.g. "\xxx\xxx.txt")</param>
    ''' <returns></returns>
    ''' <remarks></remarks>
    Public Shared Function 添加防寫資料夾(ByVal 磁碟機名稱 As String, ByVal 資料夾路徑 As String) As Boolean
        If Not SendToDriver(磁碟機名稱, SET_LAST_DISABLE_DOCUMENT_DEVICE_NAME) Then Return False
        If Not SendToDriver(資料夾路徑, SET_LAST_DISABLE_DOCUMENT_PATH) Then Return False
        Return SendToDriver(NEW_DISABLE_DOCUMENT)
    End Function

    Public Shared Function 用磁碟機名稱移除防刪文件(ByVal 磁碟機名稱 As String) As Boolean
        Return SendToDriver(磁碟機名稱, DEL_TARGET_FILE_BY_FILE_DEVICE_NAME)
    End Function

    Public Shared Function 用文件路徑移除防刪文件(ByVal 文件路徑 As String) As Boolean
        Return SendToDriver(文件路徑, DEL_TARGET_FILE_BY_FILE_NAME)
    End Function

    Public Shared Function 移除防讀文件(ByVal 文件完整路徑 As String) As Boolean
        Return SendToDriver("\??\" & 文件完整路徑, DEL_LOCK_FILE_BY_FILE_FULL_PATH)
    End Function

    Public Shared Function 用磁碟機名稱移除防寫文件(ByVal 磁碟機名稱 As String) As Boolean
        Return SendToDriver(磁碟機名稱, DEL_DISABLE_FILE_BY_FILE_DEVICE_NAME)
    End Function

    Public Shared Function 用文件路徑移除防寫文件(ByVal 文件路徑 As String) As Boolean
        Return SendToDriver(文件路徑, DEL_DISABLE_FILE_BY_FILE_NAME)
    End Function

    Public Shared Function 移除防刪資料夾(ByVal 資料夾路徑 As String) As Boolean
        Return SendToDriver(資料夾路徑, DEL_TARGET_DOCUMENT_BY_PATH)
    End Function

    Public Shared Function 移除防讀資料夾(ByVal 資料夾完整路徑 As String) As Boolean
        Return SendToDriver("\??\" & 資料夾完整路徑, DEL_LOCK_DOCUMENT_BY_FULL_PATH)
    End Function

    Public Shared Function 移除防寫資料夾(ByVal 資料夾路徑 As String) As Boolean
        Return SendToDriver(資料夾路徑, DEL_DISABLE_DOCUMENT_BY_PATH)
    End Function

    Public Shared Function SSDT_Hook_On() As Boolean
        Return SendToDriver("On", SSDT_HOOK)
    End Function

    Public Shared Function SSDT_Hook_Off() As Boolean
        Return SendToDriver("Off", SSDT_UNHOOK)
    End Function

    Public Shared Function SSDT_Hook_Init() As Boolean
        Return SendToDriver("Init", SSDT_INIT)
    End Function

End Class
