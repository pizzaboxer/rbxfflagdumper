using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using PeNet;
using RbxFFlagDumper.Lib.Exceptions;

namespace RbxFFlagDumper.Lib
{
    public static class StudioFFlagDumper
    {
        /// <summary>
        /// Consolidated function for dumping all flags (both C++ and Lua).
        /// </summary>
        /// <param name="studioPath"></param>
        /// <returns>
        /// A list of flags prefixed with a [C++] or [Lua] indicator.
        /// </returns>
        /// <exception cref="CppDumpException">
        /// Thrown when an issue with C++ dumping occurs.
        /// </exception>
        public static List<string> DumpAllFlags(string studioPath)
        {
            var list = new List<string>();

            var cppFlags = DumpCppFlags(Path.Combine(studioPath, "RobloxStudioBeta.exe"));
            var luaFlags = DumpLuaFlags(Path.Combine(studioPath, "ExtraContent"));
            var commonFlags = cppFlags.Intersect(luaFlags);

            list.AddRange(cppFlags.Where(x => !commonFlags.Contains(x)).Select(x => "[C++] " + x));
            list.AddRange(luaFlags.Where(x => !commonFlags.Contains(x)).Select(x => "[Lua] " + x));
            list.AddRange(commonFlags.Select(x => "[Com] " + x));

            return list.OrderBy(x => x.Substring(6)).ToList();
        }

        /// <summary>
        /// Dumps all Lua defined flags found within the Studio CoreScripts
        /// </summary>
        /// <param name="extraContentPath"></param>
        /// <returns></returns>
        public static List<string> DumpLuaFlags(string extraContentPath)
        {
            var finalList = new List<string>();

            foreach (var file in Directory.GetFiles(extraContentPath, "*.lua", SearchOption.AllDirectories))
            {
                string contents = File.ReadAllText(file);

                var matches = Regex.Matches(contents, "game:(?:Get|Define)Fast(Flag|Int|String)\\(\\\"(\\w+)\\\"\\)").Cast<Match>();
                var userMatches = Regex.Matches(contents, "(?:IsUserFeatureEnabled|getUserFlag)\\(\\\"(\\w+)\\\"\\)").Cast<Match>();

                foreach (var match in matches)
                {
                    string flag = string.Format("F{0}{1}", match.Groups[1], match.Groups[2]);

                    if (!finalList.Contains(flag))
                        finalList.Add(flag);
                }

                foreach (var match in userMatches)
                {
                    string flag = string.Format("FFlag{0}", match.Groups[1]);

                    if (!finalList.Contains(flag) && flag != "FFlagUserDoStuff")
                        finalList.Add(flag);
                }
            }

            finalList.Sort();
            return finalList;
        }

        /// <summary>
        /// Dumps all C++ defined flags found within the RobloxStudioBeta executable.
        /// </summary>
        /// <param name="studioExePath"></param>
        /// <returns></returns>
        /// <exception cref="CppDumpException">
        /// Thrown when an issue with C++ dumping occurs.
        /// </exception>
        /// <remarks>
        /// Modern Studio builds no longer register flags through per-flag code thunks in
        /// <c>.text</c>. Instead <c>.rdata</c> holds an 8 byte aligned table of descriptor
        /// records. A flag descriptor is:
        /// <code>
        ///   +0x00  const char* name     ; absolute VA of the flag name in .rdata
        ///   +0x08  size_t      nameLen  ; length of the name (excluding the null)
        ///   +0x10  void*       variable ; absolute VA of the mutable value in .data
        ///   +0x18  uint32      scope    ; 1 = static "F", 2 = dynamic "DF", 4 = synced "SF"
        ///   +0x1C  uint32      type     ; 0/1 = Flag, 2 = Int, 3 = String, 4 = Log
        /// </code>
        /// Versioned flags additionally have a record in the same region whose third field
        /// is a small integer version rather than a <c>.data</c> pointer:
        /// <code>
        ///   +0x00  const char* name     ;
        ///   +0x08  size_t      nameLen  ;
        ///   +0x10  size_t      version  ; appended to the flag name when greater than 1
        /// </code>
        /// </remarks>
        public static List<string> DumpCppFlags(string studioExePath)
        {
            byte[] binary = File.ReadAllBytes(studioExePath);
            var pe = new PeFile(binary);

            ulong imageBase = pe.ImageNtHeaders.OptionalHeader.ImageBase;
            var sectionHeaders = pe.ImageSectionHeaders;

            var rdataHeader = sectionHeaders.First(x => x.Name == ".rdata");
            var dataHeader = sectionHeaders.First(x => x.Name == ".data");

            int rdataOffset = (int)rdataHeader.PointerToRawData;
            int rdataLength = (int)Math.Min(rdataHeader.SizeOfRawData, (uint)(binary.Length - rdataOffset)) & ~7;
            int rdataLimit = rdataOffset + rdataLength - 32;

            ulong rdataStart = imageBase + rdataHeader.VirtualAddress;
            ulong rdataEnd = rdataStart + rdataHeader.VirtualSize;

            ulong dataStart = imageBase + dataHeader.VirtualAddress;
            ulong dataEnd = dataStart + Math.Max((ulong)dataHeader.VirtualSize, (ulong)dataHeader.SizeOfRawData);

            // Bare flag name -> full typed name (e.g. "HttpBatchLimit" -> "DFIntHttpBatchLimit").
            var flags = new Dictionary<string, string>();
            // Bare flag name -> highest registered version.
            var versions = new Dictionary<string, ulong>();

            for (int pos = rdataOffset; pos <= rdataLimit; pos += 8)
            {
                ulong namePtr = BitConverter.ToUInt64(binary, pos);

                if (namePtr < rdataStart || namePtr >= rdataEnd)
                    continue;

                ulong nameLen = BitConverter.ToUInt64(binary, pos + 8);

                if (nameLen < 1 || nameLen > 256)
                    continue;

                ulong third = BitConverter.ToUInt64(binary, pos + 16);

                if (third >= dataStart && third < dataEnd)
                {
                    string scopePrefix = ScopePrefix(BitConverter.ToUInt32(binary, pos + 24));
                    string typeWord = TypeWord(BitConverter.ToUInt32(binary, pos + 28));

                    if (scopePrefix == null || typeWord == null)
                        continue;

                    int nameOff = rdataOffset + (int)(namePtr - rdataStart);
                    string name = ReadFlagName(binary, nameOff, (int)nameLen);

                    if (name != null)
                        flags[name] = scopePrefix + typeWord + name;
                }
                else if (third > 0 && third < 0x10000)
                {
                    int nameOff = rdataOffset + (int)(namePtr - rdataStart);
                    string name = ReadFlagName(binary, nameOff, (int)nameLen);

                    if (name == null)
                        continue;

                    if (!versions.TryGetValue(name, out ulong existing) || third > existing)
                        versions[name] = third;
                }
            }

            if (flags.Count < 1)
                throw new CppDumpException(
                    "No C++ flags found; the Studio flag table layout may have changed.");

            var finalList = new List<string>();

            foreach (var flag in flags)
            {
                string fullName = flag.Value;

                if (versions.TryGetValue(flag.Key, out ulong version) && version > 1)
                    fullName += version;

                finalList.Add(fullName);
            }

            finalList.Sort();
            return finalList;
        }

        /// <summary>
        /// Maps the high dword of a flag's packed type field to its data type word.
        /// Returns null for an unrecognised value so the record can be skipped.
        /// </summary>
        private static string TypeWord(uint dataType)
        {
            switch (dataType)
            {
                case 0:
                case 1:
                    return "Flag";
                case 2:
                    return "Int";
                case 3:
                    return "String";
                case 4:
                    return "Log";
                default:
                    return null;
            }
        }

        /// <summary>
        /// Maps the low dword of a flag's packed type field to its scope prefix.
        /// Returns null for an unrecognised value so the record can be skipped.
        /// </summary>
        private static string ScopePrefix(uint scope)
        {
            switch (scope)
            {
                case 1:
                    return "F";
                case 2:
                    return "DF";
                case 4:
                    return "SF";
                default:
                    return null;
            }
        }

        /// <summary>
        /// Reads a flag name of exactly <paramref name="length"/> word characters
        /// (letters, digits and underscore) terminated by a null byte. Returns null when
        /// the bytes do not form a valid name, which rejects coincidental records.
        /// </summary>
        private static string ReadFlagName(byte[] binary, int offset, int length)
        {
            if (offset < 0 || offset + length + 1 > binary.Length)
                return null;

            if (binary[offset + length] != 0)
                return null;

            var chars = new char[length];

            for (int i = 0; i < length; i++)
            {
                byte b = binary[offset + i];

                bool isWordChar = (b >= '0' && b <= '9')
                               || (b >= 'A' && b <= 'Z')
                               || (b >= 'a' && b <= 'z')
                               || b == '_';

                if (!isWordChar)
                    return null;

                chars[i] = (char)b;
            }

            return new string(chars);
        }
    }
}
