using System;
using System.Collections.Generic;
using System.DirectoryServices.AccountManagement;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using System.Linq;
using System.DirectoryServices;
using System.IO;

namespace DomainComputerList
{
    class Program
    {
        // P/Invoke declarations for advapi32.dll
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(
            string lpMachineName,
            string lpDatabaseName,
            uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        // SC_MANAGER_ALL_ACCESS constant
        private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;

        static async Task Main(string[] args)
        {
            try
            {
                var options = ParseArguments(args);

                if (options.ShowHelp)
                {
                    ShowHelp();
                    return;
                }

                List<string> computers;

                // If specific computer is specified, test only that one
                if (!string.IsNullOrEmpty(options.ComputerName))
                {
                    computers = new List<string> { options.ComputerName };
                    Console.WriteLine($"Testing specific computer: {options.ComputerName}\n");
                }
                else
                {
                    // Get all domain computers
                    computers = GetDomainComputers(options.Domain, options.DomainController);
                    Console.WriteLine($"Found {computers.Count} computers in the domain.\n");
                }

                Console.WriteLine("Testing connectivity and administrative access...\n");
                Console.WriteLine("{0,-30} {1,-15} {2,-15} {3}", "Computer Name", "Online", "Admin Handle", "C$ Writable");
                Console.WriteLine(new string('-', 75));

                if (options.UseAsync)
                {
                    await ProcessComputersAsync(computers);
                }
                else
                {
                    ProcessComputersSync(computers);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            Console.WriteLine("");
        }

        static void ShowHelp()
        {
            Console.WriteLine("Domain Computer Admin Access Tester");
            Console.WriteLine("\nUsage:");
            Console.WriteLine("  DomainComputerList.exe [options]");
            Console.WriteLine("\nOptions:");
            Console.WriteLine("  --async              Process computers asynchronously (faster)");
            Console.WriteLine("  --domain <name>      Specify domain name (e.g., contoso.com)");
            Console.WriteLine("  --dc <server>        Specify domain controller");
            Console.WriteLine("  --computer <name>    Test a specific computer only");
            Console.WriteLine("  --help               Show this help message");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  DomainComputerList.exe");
            Console.WriteLine("  DomainComputerList.exe --async");
            Console.WriteLine("  DomainComputerList.exe --domain contoso.com --dc dc01.contoso.com");
            Console.WriteLine("  DomainComputerList.exe --computer SERVER01 --async");
        }

        static CommandLineOptions ParseArguments(string[] args)
        {
            var options = new CommandLineOptions();

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLower())
                {
                    case "--async":
                        options.UseAsync = true;
                        break;
                    case "--domain":
                        if (i + 1 < args.Length)
                            options.Domain = args[++i];
                        break;
                    case "--dc":
                        if (i + 1 < args.Length)
                            options.DomainController = args[++i];
                        break;
                    case "--computer":
                        if (i + 1 < args.Length)
                            options.ComputerName = args[++i];
                        break;
                    case "--help":
                    case "-h":
                    case "/?":
                        options.ShowHelp = true;
                        break;
                }
            }

            return options;
        }

        static void ProcessComputersSync(List<string> computers)
        {
            foreach (string computerName in computers)
            {
                ProcessComputer(computerName);
            }
        }

        static async Task ProcessComputersAsync(List<string> computers)
        {
            var tasks = computers.Select(computer => Task.Run(() => ProcessComputer(computer)));
            await Task.WhenAll(tasks);
        }

        static void ProcessComputer(string computerName)
        {
            // First check if the computer is online
            bool isOnline = IsComputerOnline(computerName);

            // Check if this is the local machine
            bool isLocalMachine = IsLocalMachine(computerName);

            // Get FQDN of the computerName
            string fqdn = GetFqdn(computerName);

            lock (Console.Out)
            {
                Console.Write("{0,-30} {1,-15} ", fqdn, isOnline ? "Yes" : "No");

                if (isOnline)
                {
                    bool hasAdminAccess = false;
                    bool cShareWritable = false;

                    if (isLocalMachine)
                    {
                        Console.Write("(Local) ");
                        // For local machine, check local admin group membership
                        //hasAdminAccess = IsLocalAdministrator();
                    }
                    else
                    {
                        // For remote machines, use the SC Manager method
                        hasAdminAccess = TestAdminAccess(computerName);

                        // If we have admin access, test C$ share writability
                        if (hasAdminAccess)
                        {
                            cShareWritable = TestCShareWritable(computerName);
                        }
                    }

                    Console.Write("{0,-15} ", hasAdminAccess ? "Yes" : "No");
                    Console.WriteLine(hasAdminAccess ? (cShareWritable ? "Yes" : "No") : "N/A");
                }
                else
                {
                    Console.WriteLine("{0,-15} {1}", "N/A", "N/A");
                }
            }
        }

        static bool TestCShareWritable(string computerName)
        {
            string testFilePath = null;
            try
            {
                // Construct the UNC path to C$
                string cSharePath = $"\\\\{computerName}\\C$";

                // Generate a unique test filename
                string testFileName = $"__test_write_{Guid.NewGuid()}.tmp";
                testFilePath = Path.Combine(cSharePath, testFileName);

                // Try to create and write to a test file
                File.WriteAllText(testFilePath, "test");

                // If we got here, write was successful
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                // Access denied
                return false;
            }
            catch (IOException)
            {
                // IO error (could be network issue or permissions)
                return false;
            }
            catch (Exception)
            {
                // Any other error
                return false;
            }
            finally
            {
                // Clean up the test file if it was created
                if (testFilePath != null)
                {
                    try
                    {
                        if (File.Exists(testFilePath))
                        {
                            File.Delete(testFilePath);
                        }
                    }
                    catch
                    {
                        // Ignore cleanup errors
                    }
                }
            }
        }

        static bool IsLocalMachine(string computerName)
        {
            try
            {
                string localHostName = Environment.MachineName.ToUpper();
                string targetHostName = computerName.ToUpper();

                // Remove domain suffix if present
                if (targetHostName.Contains("."))
                {
                    targetHostName = targetHostName.Split('.')[0];
                }

                return localHostName == targetHostName;
            }
            catch
            {
                return false;
            }
        }

        static bool IsLocalAdministrator()
        {
            try
            {
                // Get the local Administrators group using DirectoryEntry
                using (var localMachine = new System.DirectoryServices.DirectoryEntry("WinNT://.,Computer"))
                {
                    using (var admGroup = localMachine.Children.Find("Administrators", "group"))
                    {
                        // Get current user identity
                        var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                        string currentUser = identity.Name;

                        // Invoke the Members method to get all members
                        object members = admGroup.Invoke("Members");

                        foreach (object member in (System.Collections.IEnumerable)members)
                        {
                            using (var memberEntry = new System.DirectoryServices.DirectoryEntry(member))
                            {
                                string memberPath = memberEntry.Path.Replace("WinNT://", "");

                                // Check if current user matches this member
                                if (currentUser.EndsWith(memberPath.Replace("/", "\\"), StringComparison.OrdinalIgnoreCase))
                                {
                                    return true;
                                }

                                // Also check the SID
                                byte[] sidBytes = (byte[])memberEntry.Properties["objectSid"].Value;
                                var memberSid = new System.Security.Principal.SecurityIdentifier(sidBytes, 0);

                                if (identity.User.Equals(memberSid))
                                {
                                    return true;
                                }

                                // Check if it's a group that the user is member of
                                foreach (var userGroup in identity.Groups)
                                {
                                    if (userGroup.Equals(memberSid))
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.Write($"(Error: {ex.Message}) ");
                return false;
            }
        }

        static string GetFqdn(string host)
        {
            try
            {
                var entry = System.Net.Dns.GetHostEntry(host);
                return entry.HostName;
            }
            catch
            {
                return host; // fallback
            }
        }
        static bool IsComputerOnline(string computerName)
        {
            try
            {
                using (Ping ping = new Ping())
                {
                    // Send a ping with a 1 second timeout
                    PingReply reply = ping.Send(computerName, 1000);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }

        static bool TestAdminAccess(string computerName)
        {
            IntPtr handle = IntPtr.Zero;

            try
            {
                // Attempt to open SC Manager with full access rights
                // 0xF003F - SC_MANAGER_ALL_ACCESS
                handle = OpenSCManager($"\\\\{computerName}", "ServicesActive", SC_MANAGER_ALL_ACCESS);

                if (handle != IntPtr.Zero)
                {
                    // Successfully opened - we have admin access
                    return true;
                }
                else
                {
                    // Failed to open - get the last Win32 error for debugging
                    int lastError = Marshal.GetLastWin32Error();
                    string errorMessage = new Win32Exception(lastError).Message;
                    // Uncomment the line below for verbose error messages
                    // Console.Write($" (Error: {errorMessage})");
                    return false;
                }
            }
            catch (Exception ex)
            {
                // Uncomment the line below for verbose error messages
                // Console.Write($" (Exception: {ex.Message})");
                return false;
            }
            finally
            {
                // Always close the handle if it was opened
                if (handle != IntPtr.Zero)
                {
                    CloseServiceHandle(handle);
                }
            }
        }

        static List<string> GetDomainComputers(string domain = null, string domainController = null)
        {
            List<string> computerNames = new List<string>();

            try
            {
                PrincipalContext context = null;

                // Determine which constructor to use based on provided parameters
                if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(domainController))
                {
                    Console.WriteLine($"Connecting to domain: {domain} via DC: {domainController}");

                    // Try with explicit credentials context first
                    try
                    {
                        context = new PrincipalContext(ContextType.Domain, domain, domainController);
                    }
                    catch
                    {
                        Console.WriteLine("Failed with domain+DC. Trying DC only...");
                        context = new PrincipalContext(ContextType.Domain, domainController);
                    }
                }
                else if (!string.IsNullOrEmpty(domain))
                {
                    Console.WriteLine($"Connecting to domain: {domain}");
                    context = new PrincipalContext(ContextType.Domain, domain);
                }
                else if (!string.IsNullOrEmpty(domainController))
                {
                    Console.WriteLine($"Connecting via DC: {domainController}");
                    context = new PrincipalContext(ContextType.Domain, domainController);
                }
                else
                {
                    Console.WriteLine("Connecting to current domain...");
                    context = new PrincipalContext(ContextType.Domain);
                }

                using (context)
                {
                    // Create a computer principal to use as a query filter
                    using (ComputerPrincipal computer = new ComputerPrincipal(context))
                    {
                        // Create a searcher to find all computers
                        using (PrincipalSearcher searcher = new PrincipalSearcher(computer))
                        {
                            foreach (Principal result in searcher.FindAll())
                            {
                                ComputerPrincipal comp = result as ComputerPrincipal;
                                if (comp != null && !string.IsNullOrEmpty(comp.Name))
                                {
                                    computerNames.Add(comp.Name);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error connecting to domain: {ex.Message}");
                Console.WriteLine($"Error type: {ex.GetType().Name}");
                if (ex.InnerException != null)
                {
                    Console.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                Console.WriteLine("\nTroubleshooting tips:");
                Console.WriteLine("1. Verify DNS resolution of the domain/DC");
                Console.WriteLine("2. Check if LDAP ports (389/636/3268/3269) are accessible");
                Console.WriteLine("3. Try using just --dc without --domain parameter");
                Console.WriteLine("4. Try using the DC's FQDN instead of IP address");
                Console.WriteLine("5. Ensure you have domain query permissions");
                throw;
            }

            return computerNames;
        }
    }

    class CommandLineOptions
    {
        public bool UseAsync { get; set; }
        public string Domain { get; set; }
        public string DomainController { get; set; }
        public string ComputerName { get; set; }
        public bool ShowHelp { get; set; }
    }
}