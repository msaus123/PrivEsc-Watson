using System;
using System.Collections.Generic;

using Watson.Msrc;
using Watson.SuspectFiles;

namespace Watson
{
    class Program
    {
        static void Main(string[] args)
        {
            Info.PrintLogo();

            // Supported versions
            var supportedVersions = new Dictionary<int, string>()
            {
                { 10240, "1507" }, { 10586, "1511" }, { 14393, "1607" }, { 15063, "1703" }, { 16299, "1709" },
                { 17134, "1803" }, { 17763, "1809" }, { 18362, "1903" }, { 18363, "1909" }, { 19041, "2004" }
            };
            var oldSupportedVersions = new Dictionary<int, string>()
            {
                { 6000, "6000" }, { 6001, "6001"}, { 6002, "6002"}, { 7600, "7600"}, { 9200, "9200"}, { 9600, "9600"}
            };

            // Get OS Build number
            var buildNumber = Wmi.GetBuildNumber();
            if (buildNumber != 0)
            {
                string version = "";
                if (supportedVersions.ContainsKey(buildNumber))
                {
                    version = supportedVersions[buildNumber];
                    Console.WriteLine(" [*] OS Version: {0} ({1})", version, buildNumber);
                }                
            }
            else
            {
                Console.Error.WriteLine(" [!] Could not retrieve Windows BuildNumber");
                return;
            }   

            if (!supportedVersions.ContainsKey(buildNumber) && !oldSupportedVersions.ContainsKey(buildNumber))
            {
                Console.Error.WriteLine(" [!] Windows version not supported");
                return;
            }

            SystemInfo sysInfo = null;

            if ( oldSupportedVersions.ContainsKey(buildNumber))
            {
                sysInfo = SystemInfo.Collect();
                SystemInfoHelpers.PrintInfo(sysInfo);
            }

            // List of KBs installed
            Console.WriteLine(" [*] Enumerating installed KBs...");
            var installedKBs = Wmi.GetInstalledKBs();

#if DEBUG
            Console.WriteLine();

            foreach (var kb in installedKBs)
            {
                Console.WriteLine(" {0}", kb);
            }
                
            Console.WriteLine();
#endif

            // List of Vulnerabilities
            var vulnerabiltiies = new VulnerabilityCollection();

            if (oldSupportedVersions.ContainsKey(buildNumber))
            {
                OldVersion(vulnerabiltiies, sysInfo);
            }
            else
            {
                // Check each one
                CVE_2019_0836.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_0841.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1064.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1130.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1253.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1315.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1385.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1388.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2019_1405.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2020_0668.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2020_0683.Check(vulnerabiltiies, buildNumber, installedKBs);
                CVE_2020_1013.Check(vulnerabiltiies, buildNumber, installedKBs);

                // Print the results
                vulnerabiltiies.ShowResults();
            }
        }

        private static void OldVersion(VulnerabilityCollection vulnerabilities, SystemInfo sysInfo)
        {
            // ntoskrnl.exe
            NtoskrnlExe.Check(vulnerabilities, sysInfo);

            // win32k.sys
            Win32kSys.Check(vulnerabilities, sysInfo);

            // winsrv.dll
            WinsrvDll.Check(vulnerabilities, sysInfo);

            // afd.sys
            AfdSys.Check(vulnerabilities, sysInfo);

            // schedsvc.dll
            SchedsvcDll.Check(vulnerabilities, sysInfo);

            // seclogon.dll
            SeclogonDll.Check(vulnerabilities, sysInfo);

            // mrxdav.sys
            MrxdavSys.Check(vulnerabilities, sysInfo);

            // rpcrt4.dll
            Rpcrt4Dll.Check(vulnerabilities, sysInfo);

            // atmfd.dll
            AtmfdDll.Check(vulnerabilities, sysInfo);

            // winload.exe
            WinloadExe.Check(vulnerabilities, sysInfo);

            // win32kfull.sys
            Win32kfullSys.Check(vulnerabilities, sysInfo);

            // gdi32.dll
            Gdi32Dll.Check(vulnerabilities, sysInfo);

            // gdiplus.dll
            GdiplusDll.Check(vulnerabilities, sysInfo);

            // gpprefcl.dll
            GpprefclDll.Check(vulnerabilities, sysInfo);

            // pcadm.dll
            PcadmDll.Check(vulnerabilities, sysInfo);

            // coremessaging.dll
            CoremessagingDll.Check(vulnerabilities, sysInfo);

            // and we're done... print results
            vulnerabilities.ShowResults();
        }
    }
}