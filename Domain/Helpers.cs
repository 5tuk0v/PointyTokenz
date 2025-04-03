using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using Windows.Win32.Security;
using Windows.Win32.Foundation;

using static Windows.Win32.PInvoke;
using System.Text;

namespace PointyTokenz.Domain
{
    class Helpers
    {
        public static unsafe bool EnablePrivilege(string privilege)
        {
            // Get a handle to our own process token
            SafeFileHandle ownToken;

            if (!OpenProcessToken(GetCurrentProcess_SafeHandle(), TOKEN_ACCESS_MASK.TOKEN_ADJUST_PRIVILEGES, out ownToken))
            {
                Console.WriteLine($"[x] Failed to open the process token : {Marshal.GetLastWin32Error()}");
                return false;
            }

            // Lookup the privilege LUID from the privilege name
            LUID privilegeLuid;
            if (!LookupPrivilegeValue(null, privilege, out privilegeLuid))
            {
                Console.WriteLine($"[x] Failed to lookup the privilege value for {privilege} : {Marshal.GetLastWin32Error()}");
                return false;
            }

            // Prepare the privilege adjustment struct
            var newPrivilege = new TOKEN_PRIVILEGES();
            newPrivilege.PrivilegeCount = 1;
            newPrivilege.Privileges[0].Luid = privilegeLuid;
            newPrivilege.Privileges[0].Attributes = TOKEN_PRIVILEGES_ATTRIBUTES.SE_PRIVILEGE_ENABLED;

            // Enable the specified privilege
            if (!AdjustTokenPrivileges(ownToken, false, &newPrivilege, (uint)Marshal.SizeOf(newPrivilege), null, null))
            {
                Console.WriteLine($"[x] Failed to adjust the token privileges : {Marshal.GetLastWin32Error()}");
                return false;
            }

            // Check if the change was successful
            int lastError = Marshal.GetLastWin32Error();
            if (lastError == 0)
            {
                Console.WriteLine($"[*] Successfully enabled privilege '{privilege}'.");
            }
            else if (lastError == (int)WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED)
            {
                Console.WriteLine($"[!] Warning: The requested privilege '{privilege}' was not assigned : {Marshal.GetLastWin32Error()}");
            }
            else
            {
                Console.WriteLine($"[x] Failed to adjust token privileges : {Marshal.GetLastWin32Error()}");
            }

            // Close the token handle
            ownToken.Dispose();

            return true;
        }

        // Helper function to get token information, thanks to Copilot
        public static unsafe bool TokenInfo<T>(SafeFileHandle token, TOKEN_INFORMATION_CLASS tokenInfoClass, out T tokenInfo) where T : unmanaged
        {
            // Get the required buffer size
            uint tokenInfoSize = 0;
            WIN32_ERROR error = 0;

            if (!GetTokenInformation(token, tokenInfoClass, null, 0, out tokenInfoSize))
            {
                error = (WIN32_ERROR)Marshal.GetLastWin32Error();
                if (error != WIN32_ERROR.ERROR_INSUFFICIENT_BUFFER && error != WIN32_ERROR.ERROR_BAD_LENGTH)
                {
                    Console.WriteLine($"[x] Unexpected failure to get token info size: {error}");
                    tokenInfo = default;
                    return false;
                }
            }

            // Allocate the buffer
            byte[] tokenInfoBuffer = new byte[tokenInfoSize];
            fixed (byte* tokenInfoBufferPtr = tokenInfoBuffer)
            {
                // Get the token information
                if (!GetTokenInformation(token, tokenInfoClass, tokenInfoBufferPtr, tokenInfoSize, out tokenInfoSize))
                {
                    Console.WriteLine($"[x] Failed to get the token information : {Marshal.GetLastWin32Error()}");
                    tokenInfo = default;
                    return false;
                }

                // Special handling for TOKEN_ELEVATION_TYPE enum
                if (typeof(T) == typeof(TOKEN_ELEVATION_TYPE))
                {
                    // If it's a TOKEN_ELEVATION_TYPE enum, marshal it from the raw byte buffer directly
                    tokenInfo = (T)(object)(Marshal.ReadInt32((IntPtr)tokenInfoBufferPtr));
                }
                // Special handling for TOKEN_PRIVILEGES structure
                /*else if (typeof(T) == typeof(TOKEN_PRIVILEGES))
                {
                    // Marshal the TOKEN_PRIVILEGES structure first
                    tokenInfo = Marshal.PtrToStructure<T>((IntPtr)tokenInfoBufferPtr);

                    // Access the Privileges array (of type VariableLengthInlineArray<LUID_AND_ATTRIBUTES>)
                    TOKEN_PRIVILEGES privileges = (TOKEN_PRIVILEGES)(object)tokenInfo;

                    // The array will be marshaled as part of the structure
                    IntPtr privilegesPtr = (IntPtr)(tokenInfoBufferPtr + Marshal.SizeOf<TOKEN_PRIVILEGES>());
                    privileges.Privileges = Marshal.PtrToStructure<Windows.Win32.VariableLengthInlineArray<LUID_AND_ATTRIBUTES>>(privilegesPtr);

                    // Reassign back to tokenInfo
                    tokenInfo = (T)(object)privileges;
                }*/
                else
                {
                    // Marshal normally for other types
                    tokenInfo = Marshal.PtrToStructure<T>((IntPtr)tokenInfoBufferPtr);
                }
            }

            return true;
        }

        // Source: https://github.com/antonioCoco/RunasCs/blob/master/RunasCs.cs
        public class WindowStationDACL
        {

            private const int UOI_NAME = 2;
            private const int ERROR_INSUFFICIENT_BUFFER = 122;
            private const uint SECURITY_DESCRIPTOR_REVISION = 1;
            private const uint ACL_REVISION = 2;
            private const uint MAXDWORD = 0xffffffff;
            private const byte ACCESS_ALLOWED_ACE_TYPE = 0x0;
            private const byte CONTAINER_INHERIT_ACE = 0x2;
            private const byte INHERIT_ONLY_ACE = 0x8;
            private const byte OBJECT_INHERIT_ACE = 0x1;
            private const byte NO_PROPAGATE_INHERIT_ACE = 0x4;
            private const int NO_ERROR = 0;
            private const int ERROR_INVALID_FLAGS = 1004; // On Windows Server 2003 this error is/can be returned, but processing can still continue

            [Flags]
            private enum ACCESS_MASK : uint
            {
                DELETE = 0x00010000,
                READ_CONTROL = 0x00020000,
                WRITE_DAC = 0x00040000,
                WRITE_OWNER = 0x00080000,
                SYNCHRONIZE = 0x00100000,

                STANDARD_RIGHTS_REQUIRED = 0x000F0000,

                STANDARD_RIGHTS_READ = 0x00020000,
                STANDARD_RIGHTS_WRITE = 0x00020000,
                STANDARD_RIGHTS_EXECUTE = 0x00020000,

                STANDARD_RIGHTS_ALL = 0x001F0000,

                SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

                ACCESS_SYSTEM_SECURITY = 0x01000000,

                MAXIMUM_ALLOWED = 0x02000000,

                GENERIC_READ = 0x80000000,
                GENERIC_WRITE = 0x40000000,
                GENERIC_EXECUTE = 0x20000000,
                GENERIC_ALL = 0x10000000,
                GENERIC_ACCESS = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL,

                DESKTOP_READOBJECTS = 0x00000001,
                DESKTOP_CREATEWINDOW = 0x00000002,
                DESKTOP_CREATEMENU = 0x00000004,
                DESKTOP_HOOKCONTROL = 0x00000008,
                DESKTOP_JOURNALRECORD = 0x00000010,
                DESKTOP_JOURNALPLAYBACK = 0x00000020,
                DESKTOP_ENUMERATE = 0x00000040,
                DESKTOP_WRITEOBJECTS = 0x00000080,
                DESKTOP_SWITCHDESKTOP = 0x00000100,
                DESKTOP_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                            DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                            DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
                            STANDARD_RIGHTS_REQUIRED),

                WINSTA_ENUMDESKTOPS = 0x00000001,
                WINSTA_READATTRIBUTES = 0x00000002,
                WINSTA_ACCESSCLIPBOARD = 0x00000004,
                WINSTA_CREATEDESKTOP = 0x00000008,
                WINSTA_WRITEATTRIBUTES = 0x00000010,
                WINSTA_ACCESSGLOBALATOMS = 0x00000020,
                WINSTA_EXITWINDOWS = 0x00000040,
                WINSTA_ENUMERATE = 0x00000100,
                WINSTA_READSCREEN = 0x00000200,
                WINSTA_ALL = (WINSTA_ACCESSCLIPBOARD | WINSTA_ACCESSGLOBALATOMS |
                           WINSTA_CREATEDESKTOP | WINSTA_ENUMDESKTOPS |
                           WINSTA_ENUMERATE | WINSTA_EXITWINDOWS |
                           WINSTA_READATTRIBUTES | WINSTA_READSCREEN |
                           WINSTA_WRITEATTRIBUTES | DELETE |
                           READ_CONTROL | WRITE_DAC |
                           WRITE_OWNER)
            }

            [Flags]
            private enum SECURITY_INFORMATION : uint
            {
                OWNER_SECURITY_INFORMATION = 0x00000001,
                GROUP_SECURITY_INFORMATION = 0x00000002,
                DACL_SECURITY_INFORMATION = 0x00000004,
                SACL_SECURITY_INFORMATION = 0x00000008,
                UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
                UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
                PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
                PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
            }

            private enum ACL_INFORMATION_CLASS
            {
                AclRevisionInformation = 1,
                AclSizeInformation = 2
            }

            private enum SID_NAME_USE
            {
                SidTypeUser = 1,
                SidTypeGroup,
                SidTypeDomain,
                SidTypeAlias,
                SidTypeWellKnownGroup,
                SidTypeDeletedAccount,
                SidTypeInvalid,
                SidTypeUnknown,
                SidTypeComputer
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct SidIdentifierAuthority
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
                public byte[] Value;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct ACL_SIZE_INFORMATION
            {
                public uint AceCount;
                public uint AclBytesInUse;
                public uint AclBytesFree;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct ACE_HEADER
            {
                public byte AceType;
                public byte AceFlags;
                public short AceSize;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct ACCESS_ALLOWED_ACE
            {
                public ACE_HEADER Header;
                public ACCESS_MASK Mask;
                public uint SidStart;
            }

            [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr GetProcessWindowStation();

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool GetUserObjectInformation(IntPtr hObj, int nIndex, [Out] byte[] pvInfo, uint nLength, out uint lpnLengthNeeded);

            [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr OpenWindowStation([MarshalAs(UnmanagedType.LPTStr)] string lpszWinSta, [MarshalAs(UnmanagedType.Bool)] bool fInherit, ACCESS_MASK dwDesiredAccess);

            [DllImport("user32.dll")]
            private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, ACCESS_MASK dwDesiredAccess);

            [return: MarshalAs(UnmanagedType.Bool)]
            [DllImport("user32", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool CloseWindowStation(IntPtr hWinsta);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool CloseDesktop(IntPtr hDesktop);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool SetProcessWindowStation(IntPtr hWinSta);

            [DllImport("advapi32.dll")]
            private static extern IntPtr FreeSid(IntPtr pSid);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool GetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, out uint lpnLengthNeeded);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent, ref IntPtr pDacl, [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool GetAclInformation(IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInformation, uint nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool InitializeSecurityDescriptor(IntPtr SecurityDescriptor, uint dwRevision);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern int GetLengthSid(IntPtr pSID);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool GetAce(IntPtr aclPtr, int aceIndex, out IntPtr acePtr);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool AddAce(IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool AddAccessAllowedAce(IntPtr pAcl, uint dwAceRevision, ACCESS_MASK AccessMask, IntPtr pSid);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool SetSecurityDescriptorDacl(IntPtr sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool SetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSD);

            [DllImport("advapi32.dll", SetLastError = true)]
            private static extern bool CopySid(uint nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool LookupAccountName(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

            private IntPtr hWinsta;
            private IntPtr hDesktop;
            private IntPtr userSid;

            private IntPtr GetUserSid(string domain, string username)
            {
                IntPtr userSid = IntPtr.Zero;
                string fqan = "";//Fully qualified account names
                byte[]? Sid = null;
                uint cbSid = 0;
                StringBuilder referencedDomainName = new StringBuilder();
                uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
                SID_NAME_USE sidUse;
                int err = NO_ERROR;

                if (domain != "" && domain != ".")
                    fqan = domain + "\\" + username;
                else
                    fqan = username;

                if (!LookupAccountName(null, fqan, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                {
                    err = Marshal.GetLastWin32Error();
                    if (err == ERROR_INSUFFICIENT_BUFFER || err == ERROR_INVALID_FLAGS)
                    {
                        Sid = new byte[cbSid];
                        referencedDomainName.EnsureCapacity((int)cchReferencedDomainName);
                        err = NO_ERROR;
                        if (!LookupAccountName(null, fqan, Sid, ref cbSid, referencedDomainName, ref cchReferencedDomainName, out sidUse))
                            err = Marshal.GetLastWin32Error();
                    }
                }
                else
                {
                    string error = "The username " + fqan + " has not been found. ";
                    Console.WriteLine(error + "LookupAccountName");
                }
                if (err == 0)
                {
                    userSid = Marshal.AllocHGlobal((int)cbSid);
                    Marshal.Copy(Sid, 0, userSid, (int)cbSid);
                }
                else
                {
                    string error = "The username " + fqan + " has not been found. ";
                    Console.WriteLine(error + "LookupAccountName");
                }
                return userSid;
            }

            //Big thanks to Vanara project
            //https://github.com/dahall/Vanara/blob/9771eadebc874cfe876011c9d6588aefb62626d9/PInvoke/Security/AdvApi32/SecurityBaseApi.cs#L4656
            private void AddAllowedAceToDACL(IntPtr pDacl, ACCESS_MASK mask, byte aceFlags, uint aceSize)
            {
                int offset = Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) - Marshal.SizeOf(typeof(uint));
                ACE_HEADER AceHeader = new ACE_HEADER();
                AceHeader.AceType = ACCESS_ALLOWED_ACE_TYPE;
                AceHeader.AceFlags = aceFlags;
                AceHeader.AceSize = (short)aceSize;
                IntPtr pNewAcePtr = Marshal.AllocHGlobal((int)aceSize);
                ACCESS_ALLOWED_ACE pNewAceStruct = new ACCESS_ALLOWED_ACE();
                pNewAceStruct.Header = AceHeader;
                pNewAceStruct.Mask = mask;
                Marshal.StructureToPtr(pNewAceStruct, pNewAcePtr, false);
                IntPtr sidStartPtr = new IntPtr(pNewAcePtr.ToInt64() + offset);
                if (!CopySid((uint)GetLengthSid(this.userSid), sidStartPtr, this.userSid))
                    Console.WriteLine("CopySid");
                if (!AddAce(pDacl, ACL_REVISION, MAXDWORD, pNewAcePtr, aceSize))
                    Console.WriteLine("AddAce");
                Marshal.FreeHGlobal(pNewAcePtr);
            }

            private void AddAceToWindowStation()
            {
                uint cbSd = 0;
                bool fDaclPresent = false;
                bool fDaclExist = false;
                IntPtr pDacl = IntPtr.Zero;
                uint cbDacl = 0;
                IntPtr pSd = IntPtr.Zero;
                IntPtr pNewSd = IntPtr.Zero;
                uint cbNewDacl = 0;
                uint cbNewAce = 0;
                IntPtr pNewDacl = IntPtr.Zero;

                ACL_SIZE_INFORMATION aclSizeInfo = new ACL_SIZE_INFORMATION();
                SECURITY_INFORMATION si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
                // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
                if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, 0, out cbSd))
                {
                    if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
                    {
                        Console.WriteLine("GetUserObjectSecurity 1 size");
                    }
                }
                pSd = Marshal.AllocHGlobal((int)cbSd);
                // Obtain the security descriptor for the desktop object.
                if (!GetUserObjectSecurity(this.hWinsta, ref si, pSd, cbSd, out cbSd))
                {
                    Console.WriteLine("GetUserObjectSecurity 2");
                }
                // Get the DACL from the security descriptor.
                if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
                {
                    Console.WriteLine("GetSecurityDescriptorDacl");
                }
                // Get the size information of the DACL.
                if (pDacl == IntPtr.Zero)
                {
                    cbDacl = 0;
                }
                else
                {
                    if (!GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation))
                    {
                        Console.WriteLine("GetAclInformation");
                    }
                    cbDacl = aclSizeInfo.AclBytesInUse;
                }

                // Allocate memory for the new security descriptor.
                pNewSd = Marshal.AllocHGlobal((int)cbSd);
                // Initialize the new security descriptor.
                if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
                {
                    Console.WriteLine("InitializeSecurityDescriptor");
                }

                // Compute the size of a DACL to be added to the new security descriptor.
                cbNewAce = (uint)Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) + (uint)GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
                if (cbDacl == 0)
                    cbNewDacl = 8 + (cbNewAce * 2);//8 = sizeof(ACL)
                else
                    cbNewDacl = cbDacl + (cbNewAce * 2);

                // Allocate memory for the new DACL.
                pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
                // Initialize the new DACL.
                if (!InitializeAcl(pNewDacl, cbNewDacl, ACL_REVISION))
                {
                    Console.WriteLine("InitializeAcl");
                }

                // If the original DACL is present, copy it to the new DACL.
                if (fDaclPresent)
                {
                    // Copy the ACEs to the new DACL.
                    for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
                    {
                        IntPtr pTempAce = IntPtr.Zero;
                        // Get an ACE.
                        if (!GetAce(pDacl, dwIndex, out pTempAce))
                        {
                            Console.WriteLine("GetAce");
                        }
                        ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                        // Add the ACE to the new ACL.
                        if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                        {
                            Console.WriteLine("AddAce");
                        }
                    }
                }

                AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.GENERIC_ACCESS, CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | OBJECT_INHERIT_ACE, cbNewAce);
                AddAllowedAceToDACL(pNewDacl, ACCESS_MASK.WINSTA_ALL, NO_PROPAGATE_INHERIT_ACE, cbNewAce);
                // Assign the new DACL to the new security descriptor.
                if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
                {
                    Console.WriteLine("SetSecurityDescriptorDacl");
                }
                //  Set the new security descriptor for the desktop object.
                if (!SetUserObjectSecurity(this.hWinsta, ref si, pNewSd))
                {
                    Console.WriteLine("SetUserObjectSecurity");
                }

                Marshal.FreeHGlobal(pSd);
                Marshal.FreeHGlobal(pNewSd);
                Marshal.FreeHGlobal(pNewDacl);
            }

            private void AddAceToDesktop()
            {
                uint cbSd = 0;
                bool fDaclPresent = false;
                bool fDaclExist = false;
                IntPtr pDacl = IntPtr.Zero;
                uint cbDacl = 0;
                IntPtr pSd = IntPtr.Zero;
                IntPtr pNewSd = IntPtr.Zero;
                uint cbNewDacl = 0;
                uint cbNewAce = 0;
                IntPtr pNewDacl = IntPtr.Zero;

                ACL_SIZE_INFORMATION aclSizeInfo = new ACL_SIZE_INFORMATION();
                SECURITY_INFORMATION si = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;
                // Get required buffer size and allocate the SECURITY_DESCRIPTOR buffer.
                if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, 0, out cbSd))
                {
                    if (Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
                    {
                        Console.WriteLine("GetUserObjectSecurity 1 size");
                    }
                }
                pSd = Marshal.AllocHGlobal((int)cbSd);
                // Obtain the security descriptor for the desktop object.
                if (!GetUserObjectSecurity(this.hDesktop, ref si, pSd, cbSd, out cbSd))
                {
                    Console.WriteLine("GetUserObjectSecurity 2");
                }
                // Get the DACL from the security descriptor.
                if (!GetSecurityDescriptorDacl(pSd, out fDaclPresent, ref pDacl, out fDaclExist))
                {
                    Console.WriteLine("GetSecurityDescriptorDacl");
                }
                // Get the size information of the DACL.
                if (pDacl == IntPtr.Zero)
                {
                    cbDacl = 0;
                }
                else
                {
                    if (!GetAclInformation(pDacl, ref aclSizeInfo, (uint)Marshal.SizeOf(typeof(ACL_SIZE_INFORMATION)), ACL_INFORMATION_CLASS.AclSizeInformation))
                    {
                        Console.WriteLine("GetAclInformation");
                    }
                    cbDacl = aclSizeInfo.AclBytesInUse;
                }

                // Allocate memory for the new security descriptor.
                pNewSd = Marshal.AllocHGlobal((int)cbSd);
                // Initialize the new security descriptor.
                if (!InitializeSecurityDescriptor(pNewSd, SECURITY_DESCRIPTOR_REVISION))
                {
                    Console.WriteLine("InitializeSecurityDescriptor");
                }

                // Compute the size of a DACL to be added to the new security descriptor.
                cbNewAce = (uint)Marshal.SizeOf(typeof(ACCESS_ALLOWED_ACE)) + (uint)GetLengthSid(this.userSid) - (uint)Marshal.SizeOf(typeof(uint));
                if (cbDacl == 0)
                    cbNewDacl = 8 + cbNewAce;//8 = sizeof(ACL)
                else
                    cbNewDacl = cbDacl + cbNewAce;

                // Allocate memory for the new DACL.
                pNewDacl = Marshal.AllocHGlobal((int)cbNewDacl);
                // Initialize the new DACL.
                if (!InitializeAcl(pNewDacl, cbNewDacl, ACL_REVISION))
                {
                    Console.WriteLine("InitializeAcl");
                }

                // If the original DACL is present, copy it to the new DACL.
                if (fDaclPresent)
                {
                    // Copy the ACEs to the new DACL.
                    for (int dwIndex = 0; dwIndex < aclSizeInfo.AceCount; dwIndex++)
                    {
                        IntPtr pTempAce = IntPtr.Zero;
                        // Get an ACE.
                        if (!GetAce(pDacl, dwIndex, out pTempAce))
                        {
                            Console.WriteLine("GetAce");
                        }
                        ACE_HEADER pTempAceStruct = (ACE_HEADER)Marshal.PtrToStructure(pTempAce, typeof(ACE_HEADER));
                        // Add the ACE to the new ACL.
                        if (!AddAce(pNewDacl, ACL_REVISION, MAXDWORD, pTempAce, (uint)pTempAceStruct.AceSize))
                        {
                            Console.WriteLine("AddAce");
                        }
                    }
                }

                // Add a new ACE to the new DACL.
                if (!AddAccessAllowedAce(pNewDacl, ACL_REVISION, ACCESS_MASK.DESKTOP_ALL, this.userSid))
                {
                    Console.WriteLine("AddAccessAllowedAce");
                }

                // Assign the new DACL to the new security descriptor.
                if (!SetSecurityDescriptorDacl(pNewSd, true, pNewDacl, false))
                {
                    Console.WriteLine("SetSecurityDescriptorDacl");
                }
                //  Set the new security descriptor for the desktop object.
                if (!SetUserObjectSecurity(this.hDesktop, ref si, pNewSd))
                {
                    Console.WriteLine("SetUserObjectSecurity");
                }

                Marshal.FreeHGlobal(pSd);
                Marshal.FreeHGlobal(pNewSd);
                Marshal.FreeHGlobal(pNewDacl);
            }
            public WindowStationDACL()
            {
                this.hWinsta = IntPtr.Zero;
                this.hDesktop = IntPtr.Zero;
                this.userSid = IntPtr.Zero;
            }

            public string AddAclToActiveWindowStation(string domain, string username, int logonType)
            {
                string lpDesktop = "";
                byte[] stationNameBytes = new byte[256];
                string stationName = "";
                uint lengthNeeded = 0;
                IntPtr hWinstaSave = GetProcessWindowStation();
                if (hWinstaSave == IntPtr.Zero)
                {
                    Console.WriteLine("GetProcessWindowStation");
                }
                if (!GetUserObjectInformation(hWinstaSave, UOI_NAME, stationNameBytes, 256, out lengthNeeded))
                {
                    Console.WriteLine("GetUserObjectInformation");
                }
                stationName = Encoding.Default.GetString(stationNameBytes).Substring(0, (int)lengthNeeded - 1);
                // this should be avoided with the LOGON32_LOGON_NEW_CREDENTIALS logon type or some bug can happen in LookupAccountName()
                if (logonType != 9)
                {
                    this.hWinsta = OpenWindowStation(stationName, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC);
                    if (this.hWinsta == IntPtr.Zero)
                    {
                        Console.WriteLine("OpenWindowStation");
                    }
                    if (!SetProcessWindowStation(this.hWinsta))
                    {
                        Console.WriteLine("SetProcessWindowStation hWinsta");
                    }
                    this.hDesktop = OpenDesktop("Default", 0, false, ACCESS_MASK.READ_CONTROL | ACCESS_MASK.WRITE_DAC | ACCESS_MASK.DESKTOP_WRITEOBJECTS | ACCESS_MASK.DESKTOP_READOBJECTS);
                    if (!SetProcessWindowStation(hWinstaSave))
                    {
                        Console.WriteLine("SetProcessWindowStation hWinstaSave");
                    }
                    if (this.hWinsta == IntPtr.Zero)
                    {
                        Console.WriteLine("OpenDesktop");
                    }
                    this.userSid = GetUserSid(domain, username);
                    AddAceToWindowStation();
                    AddAceToDesktop();
                }
                lpDesktop = stationName + "\\Default";
                return lpDesktop;
            }

            public void CleanupHandles()
            {
                if (this.hWinsta != IntPtr.Zero) CloseWindowStation(this.hWinsta);
                if (this.hDesktop != IntPtr.Zero) CloseDesktop(this.hDesktop);
                if (this.userSid != IntPtr.Zero) FreeSid(this.userSid);
            }
        }
    }
}
