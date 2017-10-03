using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices.AccountManagement;

namespace OpenVpnCredentialAuth
{
    /*
     *  Server side reference implementation of user/password authentication for use with OpenVPN.
     *  This will allow credential authentication against a domain or a machine.
     *
     *  See authentication section ( auth-user-pass) in OpenVPN docs:
     *  https://openvpn.net/index.php/open-source/documentation/howto.html
     *  
     *  and --auth-user-pass-verify script method section 
     *  https://openvpn.net/index.php/open-source/documentation/manuals/65-openvpn-20x-manpage.html
     *  
     *  --script-security level [method] must be properly set as well:
     *  https://openvpn.net/index.php/open-source/documentation/manuals/427-openvpn-22.html
     *  
     *   OpenVPN will pass user and password information in Environment Variables   UserName and Password
     *   For machine auth (vs Domain Auth), the local machine name should be set in an Environment variable named MachineName
     */
    class OpenVpnCredentialAuth
    {

        static string ContextTypeMachine = "Machine";
        static string ContextTypeDomain = "Domain";

        static void Main(string[] args)
        {
            bool valid = false;

            string machineName = Environment.GetEnvironmentVariable("MachineName");
            string userid = Environment.GetEnvironmentVariable("UserName");
            string password = Environment.GetEnvironmentVariable("Password");

            if (ContextTypeDomain.Equals(Properties.Settings.Default.ContextType))
            {
                try
                {
                    using (PrincipalContext context = new PrincipalContext(ContextType.Domain, Properties.Settings.Default.Domain))
                    {
                        valid = context.ValidateCredentials(userid, password);
                    }
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine($" Error attempting {ContextTypeDomain} ValidateCredentials.", ex);
                }
            }
            else
            {
                try
                {
                    using (PrincipalContext context = new PrincipalContext(ContextType.Machine, machineName))
                    {
                        valid = context.ValidateCredentials(userid, password);
                    }
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine($" Error attempting {ContextTypeMachine} ValidateCredentials.", ex);
                }
            }

            if (valid)
            {
                System.Console.WriteLine($"User {0} authentication successful.", userid);
                Environment.Exit(0);
            }
            else
            {
                System.Console.WriteLine($"User {0} authentication failed.", userid);
                Environment.Exit(1);
            }
        }
    }
}
