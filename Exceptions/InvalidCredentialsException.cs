using System;

namespace BlackBarLabs.Security.SessionServer.Exceptions
{
    public class InvalidCredentialsException : ArgumentException
    {
        public InvalidCredentialsException(string message) : base(message)
        {
        }
    }
}
