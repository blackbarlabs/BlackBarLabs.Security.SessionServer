using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace BlackBarLabs.Security.SessionServer
{
    public static class ExtensionsThrowingExceptions
    {
        public static void ValidateArgumentIsNotNull(this object argument, string argumentName)
        {
            if (argument == null) throw new ArgumentNullException(argumentName);
        }

        public static void ValidateArgumentIsNotNullOrEmpty(this string argument, string argumentName)
        {
            argument.ValidateArgumentIsNotNull(argumentName);

            if (argument.Length == 0)
                throw new ArgumentException("Argument cannot be empty.", argumentName);
        }

        public static void ValidateArgumentIsNotNullOrEmpty(this IEnumerable<string> argument, string argumentName)
        {
            argument.ValidateArgumentIsNotNull(argumentName);

            if (!argument.Any() || argument.Any(string.IsNullOrEmpty))
            {
                throw new ArgumentException("Argument cannot be empty or contain an empty string.", argumentName);
            }
        }

        public static void ValidateArgumentIsPositive(this int value, string argumentName)
        {
            if (value >= 0) return;
            const string message = "Argument is not positive.";
            throw new ArgumentOutOfRangeException(argumentName, value, message);
        }

        public static void ValidateArgumentIsPositive(this double value, string argumentName)
        {
            if (value >= 0) return;
            const string message = "Argument is not positive.";
            throw new ArgumentOutOfRangeException(argumentName, value, message);
        }

        public static void ValidateArgumentIsGreaterThanZero(this int value, string argumentName)
        {
            if (value > 0) return;
            const string message = "Argument is not greater than zero.";
            throw new ArgumentOutOfRangeException(argumentName, value, message);
        }

        public static void ValidateArgumentIsGreaterThanZero(this double value, string argumentName)
        {
            if (value > 0) return;
            const string message = "Argument is not greater than zero.";
            throw new ArgumentOutOfRangeException(argumentName, value, message);
        }

        public static void ValidateIsLessThan(this DateTimeOffset firstDate, DateTimeOffset secondDate, string argumentName)
        {
            if (firstDate.CompareTo(secondDate) < 0) return;
            var message = string.Format(CultureInfo.InvariantCulture, "{0} is not less than {1}.", firstDate, secondDate);
            throw new ArgumentException(message, argumentName);
        }
    }
}
