using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

internal static class MemScopeFixture
{

    private const int BlockSize = 256;

    private const int OffSentinelBefore = 0x00;
    private const int OffCounter = 0x04;
    private const int OffSentinelAfter = 0x08;
    private const int OffI8Min = 0x0C;
    private const int OffI8Max = 0x0D;
    private const int OffU8Min = 0x0E;
    private const int OffU8Max = 0x0F;
    private const int OffI16Min = 0x10;
    private const int OffI16Max = 0x12;
    private const int OffU16Min = 0x14;
    private const int OffU16Max = 0x16;
    private const int OffI32Min = 0x18;
    private const int OffI32Max = 0x1C;
    private const int OffU32Min = 0x20;
    private const int OffU32Max = 0x24;
    private const int OffI64Min = 0x28;
    private const int OffI64Max = 0x30;
    private const int OffU64Max = 0x38;
    private const int OffF32Tenth = 0x40;
    private const int OffF32Nan = 0x44;
    private const int OffF32PosInf = 0x48;
    private const int OffF32NegZero = 0x4C;
    private const int OffF64Tenth = 0x50;
    private const int OffF64NegInf = 0x58;
    private const int OffF64Nan = 0x60;
    private const int OffPointerRoot = 0x68;

    private const int OffScratch = 0x80;
    private const int ScratchSize = 0x80;

    private const int StringsSize = 256;
    private const int OffUtf8Terminated = 0x00;
    private const int OffUtf8Unterminated = 0x20;
    private const int OffUtf8Invalid = 0x40;
    private const int OffUtf16Terminated = 0x50;
    private const int OffUtf16Unterminated = 0x80;
    private const int OffUtf16LoneSurrogate = 0xA0;

    private const string Utf8Text = "memscope-utf8";
    private const string Utf8UnterminatedText = "no-terminator";
    private const string Utf16Text = "memscope-utf16";
    private const string Utf16UnterminatedText = "no-term";

    private const int NodeSize = 64;
    private const int OffNode1Next = 0x10;
    private const int OffNode2Next = 0x08;
    private const int OffLeafValue = 0x00;
    private const int LeafValue = 1337;

    private const int DuplicateCount = 1024;
    private const int DuplicateValue = 0x11223344;
    private const int BoundaryRegionSize = 128 * 1024;

    private const int BoundaryStraddleOffset = (64 * 1024) - 2;
    private const int BoundaryStraddleValue = unchecked((int)0x7EEDBEEF);
    private const int PageSize = 4096;
    private const int BenchValue = 0x4D454D53;
    private const int BenchPlantStride = 1000000;

    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_NOACCESS = 0x01;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_GUARD = 0x100;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocationType, uint protect);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool VirtualProtect(IntPtr address, UIntPtr size, uint newProtect, out uint oldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetModuleHandleW([MarshalAs(UnmanagedType.LPWStr)] string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWow64Process(IntPtr process, out bool wow64);

    private const string AnchorDll = "memscope_anchor.dll";

    [DllImport(AnchorDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void anchor_set_root(IntPtr p);

    [DllImport(AnchorDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr anchor_root_address();

    private sealed class Area
    {
        public string Name;
        public IntPtr Base;
        public long Size;
        public bool Readable;
        public string Note;
    }

    private static readonly object Gate = new object();
    private static readonly List<Area> Areas = new List<Area>();
    private static readonly List<GCHandle> Pins = new List<GCHandle>();

    private static IntPtr _block;
    private static IntPtr _strings;
    private static IntPtr _node1;
    private static IntPtr _node2;
    private static IntPtr _leaf;
    private static IntPtr _duplicates;
    private static IntPtr _boundary;
    private static IntPtr _noaccess;
    private static IntPtr _guard;
    private static IntPtr _protect;
    private static IntPtr _bench = IntPtr.Zero;
    private static long _benchSize;
    private static long _benchMatches;

    private static IntPtr _anchorBase;
    private static IntPtr _rootAddress;

    private static string _pipeName;
    private static string _startupJson;

    private static int _lastSelfValue;
    private static int _externalChanges;
    private static int _lastExternalValue;

    private static volatile int _tickMs;
    private static long _churnUntilMs;
    private static readonly Stopwatch Clock = Stopwatch.StartNew();
    private static volatile bool _paused;
    private static volatile bool _stopping;

    private static int Main(string[] args)
    {
        bool withBench = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--bench")
            {
                withBench = true;
            }
            else if (args[i] == "--help" || args[i] == "-h")
            {
                Console.Error.WriteLine("MemScopeFixture [--bench]");
                Console.Error.WriteLine("  --bench  also allocate the 128 MiB benchmark workload");
                return 0;
            }
            else
            {
                Console.Error.WriteLine("unknown argument: " + args[i]);
                return 2;
            }
        }

        try
        {
            SetUpMemory(withBench);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("fixture setup failed: " + ex.Message);
            return 3;
        }

        _pipeName = "memscope-fixture-" + Guid.NewGuid().ToString("N");
        _startupJson = BuildStartupJson();

        NamedPipeServerStream server = CreatePipe();
        Console.WriteLine(_startupJson);
        Console.WriteLine("ready");
        Console.Out.Flush();

        Thread watcher = new Thread(WatchCounter);
        watcher.IsBackground = true;
        watcher.Start();

        Thread ticker = new Thread(SelfMutate);
        ticker.IsBackground = true;
        ticker.Start();

        Thread churner = new Thread(Churn);
        churner.IsBackground = true;
        churner.Start();

        int exit = ServePipe(server);

        _stopping = true;
        foreach (GCHandle pin in Pins)
        {
            if (pin.IsAllocated)
            {
                pin.Free();
            }
        }
        return exit;
    }

    private static IntPtr PinBytes(byte[] buffer, string name, string note)
    {
        GCHandle pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        Pins.Add(pin);
        IntPtr addr = pin.AddrOfPinnedObject();
        Areas.Add(new Area { Name = name, Base = addr, Size = buffer.Length, Readable = true, Note = note });
        return addr;
    }

    private static IntPtr Commit(long size, uint protect, string name, bool readable, string note)
    {
        IntPtr p = VirtualAlloc(IntPtr.Zero, new UIntPtr((ulong)size), MEM_COMMIT | MEM_RESERVE, protect);
        if (p == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                "VirtualAlloc(" + size + ", 0x" + protect.ToString("x", CultureInfo.InvariantCulture) +
                ") failed with Win32 error " + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
        }
        Areas.Add(new Area { Name = name, Base = p, Size = size, Readable = readable, Note = note });
        return p;
    }

    private static void SetUpMemory(bool withBench)
    {

        byte[] blockBytes = new byte[BlockSize];
        for (int i = OffScratch; i < OffScratch + ScratchSize; i++)
        {
            blockBytes[i] = 0xCC;
        }
        _block = PinBytes(blockBytes, "block", "pinned scalar block; see layout");

        WriteU32(_block, OffSentinelBefore, 0xA5A5A5A5u);
        Marshal.WriteInt32(_block, OffCounter, 100);

        _lastSelfValue = 100;
        WriteU32(_block, OffSentinelAfter, 0x5A5A5A5Au);

        Marshal.WriteByte(_block, OffI8Min, unchecked((byte)sbyte.MinValue));
        Marshal.WriteByte(_block, OffI8Max, (byte)sbyte.MaxValue);
        Marshal.WriteByte(_block, OffU8Min, byte.MinValue);
        Marshal.WriteByte(_block, OffU8Max, byte.MaxValue);
        Marshal.WriteInt16(_block, OffI16Min, short.MinValue);
        Marshal.WriteInt16(_block, OffI16Max, short.MaxValue);
        Marshal.WriteInt16(_block, OffU16Min, unchecked((short)ushort.MinValue));
        Marshal.WriteInt16(_block, OffU16Max, unchecked((short)ushort.MaxValue));
        Marshal.WriteInt32(_block, OffI32Min, int.MinValue);
        Marshal.WriteInt32(_block, OffI32Max, int.MaxValue);
        WriteU32(_block, OffU32Min, uint.MinValue);
        WriteU32(_block, OffU32Max, uint.MaxValue);
        Marshal.WriteInt64(_block, OffI64Min, long.MinValue);
        Marshal.WriteInt64(_block, OffI64Max, long.MaxValue);
        Marshal.WriteInt64(_block, OffU64Max, unchecked((long)ulong.MaxValue));

        WriteF32(_block, OffF32Tenth, 0.1f);
        WriteF32(_block, OffF32Nan, float.NaN);
        WriteF32(_block, OffF32PosInf, float.PositiveInfinity);
        WriteF32(_block, OffF32NegZero, -0.0f);
        WriteF64(_block, OffF64Tenth, 0.1d);
        WriteF64(_block, OffF64NegInf, double.NegativeInfinity);
        WriteF64(_block, OffF64Nan, double.NaN);

        byte[] stringBytes = new byte[StringsSize];
        for (int i = 0; i < stringBytes.Length; i++)
        {
            stringBytes[i] = 0xFF;
        }
        PlaceUtf8(stringBytes, OffUtf8Terminated, Utf8Text, true);
        PlaceUtf8(stringBytes, OffUtf8Unterminated, Utf8UnterminatedText, false);

        stringBytes[OffUtf8Invalid + 0] = 0x48;
        stringBytes[OffUtf8Invalid + 1] = 0x69;
        stringBytes[OffUtf8Invalid + 2] = 0xFF;
        stringBytes[OffUtf8Invalid + 3] = 0xFE;
        stringBytes[OffUtf8Invalid + 4] = 0x00;
        PlaceUtf16(stringBytes, OffUtf16Terminated, Utf16Text, true);
        PlaceUtf16(stringBytes, OffUtf16Unterminated, Utf16UnterminatedText, false);

        stringBytes[OffUtf16LoneSurrogate + 0] = 0x00;
        stringBytes[OffUtf16LoneSurrogate + 1] = 0xD8;
        stringBytes[OffUtf16LoneSurrogate + 2] = 0x41;
        stringBytes[OffUtf16LoneSurrogate + 3] = 0x00;
        stringBytes[OffUtf16LoneSurrogate + 4] = 0x00;
        stringBytes[OffUtf16LoneSurrogate + 5] = 0x00;
        _strings = PinBytes(stringBytes, "strings", "UTF-8 and UTF-16LE cases; 0xFF filler");

        _node1 = PinBytes(new byte[NodeSize], "node1", "chain node 1");
        _node2 = PinBytes(new byte[NodeSize], "node2", "chain node 2");
        _leaf = PinBytes(new byte[NodeSize], "leaf", "chain leaf");

        Marshal.WriteIntPtr(_node1, OffNode1Next, _node2);
        Marshal.WriteIntPtr(_node2, OffNode2Next, _leaf);
        Marshal.WriteInt32(_leaf, OffLeafValue, LeafValue);

        Marshal.WriteIntPtr(_block, OffPointerRoot, _node1);
        Marshal.WriteInt64(_block, OffPointerRoot + IntPtr.Size, unchecked((long)0xDEADBEEFCAFEBABEuL));

        anchor_set_root(_node1);
        _rootAddress = anchor_root_address();
        _anchorBase = GetModuleHandleW(AnchorDll);
        if (_anchorBase == IntPtr.Zero)
        {
            throw new InvalidOperationException(
                AnchorDll + " is not loaded; GetModuleHandleW failed with Win32 error " +
                Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
        }
        if (Marshal.ReadIntPtr(_rootAddress) != _node1)
        {
            throw new InvalidOperationException("anchor root did not take the value written to it");
        }

        byte[] dupBytes = new byte[DuplicateCount * 4];
        _duplicates = PinBytes(dupBytes, "duplicates",
            DuplicateCount + " copies of 0x" + DuplicateValue.ToString("x8", CultureInfo.InvariantCulture));
        for (int i = 0; i < DuplicateCount; i++)
        {
            Marshal.WriteInt32(_duplicates, i * 4, DuplicateValue);
        }

        _boundary = Commit(BoundaryRegionSize, PAGE_READWRITE, "boundary", true,
            "int32 0x" + BoundaryStraddleValue.ToString("x8", CultureInfo.InvariantCulture) +
            " straddles the 64 KiB mark at +0x" + BoundaryStraddleOffset.ToString("x", CultureInfo.InvariantCulture));
        Marshal.WriteInt32(_boundary, BoundaryStraddleOffset, BoundaryStraddleValue);

        _noaccess = Commit(PageSize, PAGE_NOACCESS, "noaccess", false,
            "PAGE_NOACCESS; must be reported as excluded, never read as zeroes");
        _guard = Commit(PageSize, PAGE_READWRITE | PAGE_GUARD, "guard", false,
            "PAGE_GUARD; must be reported as excluded");
        _protect = Commit(PageSize, PAGE_READWRITE, "protect", true,
            "protection changeable at runtime via the protect command");
        Marshal.WriteInt32(_protect, 0, DuplicateValue);

        if (withBench)
        {
            SetUpBench();
        }
    }

    private static void SetUpBench()
    {
        _benchSize = 128L * 1024L * 1024L;
        _bench = Commit(_benchSize, PAGE_READWRITE, "bench", true,
            "128 MiB deterministic LCG workload; " + BenchValue.ToString("x8", CultureInfo.InvariantCulture) +
            " planted every " + BenchPlantStride.ToString(CultureInfo.InvariantCulture) + " int32 slots");

        long slots = _benchSize / 4;
        uint state = 0x1234ABCDu;
        long matches = 0;
        for (long i = 0; i < slots; i++)
        {
            int value;
            if (i % BenchPlantStride == 0)
            {
                value = BenchValue;
            }
            else
            {
                state = unchecked(state * 1103515245u + 12345u);
                value = unchecked((int)state);
            }
            Marshal.WriteInt32(_bench, (int)(i * 4), value);
            if (value == BenchValue)
            {
                matches++;
            }
        }
        _benchMatches = matches;
    }

    private static void PlaceUtf8(byte[] buffer, int offset, string text, bool terminate)
    {
        byte[] encoded = Encoding.UTF8.GetBytes(text);
        Array.Copy(encoded, 0, buffer, offset, encoded.Length);
        if (terminate)
        {
            buffer[offset + encoded.Length] = 0x00;
        }
    }

    private static void PlaceUtf16(byte[] buffer, int offset, string text, bool terminate)
    {
        byte[] encoded = Encoding.Unicode.GetBytes(text);
        Array.Copy(encoded, 0, buffer, offset, encoded.Length);
        if (terminate)
        {
            buffer[offset + encoded.Length] = 0x00;
            buffer[offset + encoded.Length + 1] = 0x00;
        }
    }

    private static void WriteU32(IntPtr p, int offset, uint v)
    {
        Marshal.WriteInt32(p, offset, unchecked((int)v));
    }

    private static void WriteF32(IntPtr p, int offset, float v)
    {
        Marshal.WriteInt32(p, offset, BitConverter.ToInt32(BitConverter.GetBytes(v), 0));
    }

    private static void WriteF64(IntPtr p, int offset, double v)
    {
        Marshal.WriteInt64(p, offset, BitConverter.DoubleToInt64Bits(v));
    }

    private static void WatchCounter()
    {

        while (!_stopping)
        {
            Thread.Sleep(25);
            lock (Gate)
            {
                int now = Marshal.ReadInt32(_block, OffCounter);
                if (now != _lastSelfValue)
                {
                    _externalChanges++;
                    _lastExternalValue = now;
                    int previous = _lastSelfValue;
                    _lastSelfValue = now;
                    Console.WriteLine("external_change=" + previous.ToString(CultureInfo.InvariantCulture) +
                        "->" + now.ToString(CultureInfo.InvariantCulture));
                    Console.Out.Flush();
                }
            }
        }
    }

    private static void SelfMutate()
    {
        while (!_stopping)
        {
            int ms = _tickMs;
            if (ms <= 0 || _paused)
            {
                Thread.Sleep(20);
                continue;
            }
            Thread.Sleep(ms);
            lock (Gate)
            {
                if (_paused || _tickMs <= 0 || _stopping)
                {
                    continue;
                }
                int next = Marshal.ReadInt32(_block, OffCounter) + 1;
                Marshal.WriteInt32(_block, OffCounter, next);
                _lastSelfValue = next;
            }
        }
    }

    private static void Churn()
    {
        while (!_stopping)
        {
            if (_paused || Clock.ElapsedMilliseconds >= Interlocked.Read(ref _churnUntilMs))
            {
                Thread.Sleep(2);
                continue;
            }
            lock (Gate)
            {
                int next = Marshal.ReadInt32(_block, OffCounter) + 1;
                Marshal.WriteInt32(_block, OffCounter, next);
                _lastSelfValue = next;
            }
        }
    }

    private static string StartChurn(string[] parts)
    {
        if (parts.Length != 2)
        {
            return "err=expected_duration_ms";
        }
        int ms;
        if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out ms))
        {
            return "err=not_an_integer";
        }
        if (ms < 0 || ms > 5000)
        {
            return "err=duration_out_of_range";
        }
        Interlocked.Exchange(ref _churnUntilMs, Clock.ElapsedMilliseconds + ms);
        return "churn=" + ms.ToString(CultureInfo.InvariantCulture);
    }

    private static NamedPipeServerStream CreatePipe()
    {
        return new NamedPipeServerStream(
            _pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096);
    }

    private const int MaxLineBytes = 4096;

    private static int ServePipe(NamedPipeServerStream server)
    {
        NamedPipeServerStream current = server;
        while (true)
        {
            try
            {
                current.WaitForConnection();
            }
            catch (IOException)
            {
                current.Dispose();
                current = CreatePipe();
                continue;
            }

            while (true)
            {
                string line = ReadLineBounded(current);
                if (line == null)
                {
                    break;
                }
                string reply;
                bool exiting = Handle(line, out reply);
                WriteLine(current, reply);
                if (exiting)
                {
                    try
                    {
                        current.Flush();
                        current.Dispose();
                    }
                    catch (IOException)
                    {

                    }
                    Console.WriteLine("bye");
                    Console.Out.Flush();
                    return 0;
                }
            }

            try
            {
                current.Disconnect();
            }
            catch (InvalidOperationException)
            {

            }
        }
    }

    private static string ReadLineBounded(Stream s)
    {

        byte[] buffer = new byte[MaxLineBytes];
        int count = 0;
        while (count < MaxLineBytes)
        {
            int b;
            try
            {
                b = s.ReadByte();
            }
            catch (IOException)
            {
                return null;
            }
            if (b < 0)
            {
                return count == 0 ? null : Encoding.UTF8.GetString(buffer, 0, count);
            }
            if (b == '\n')
            {
                int end = count;
                if (end > 0 && buffer[end - 1] == '\r')
                {
                    end--;
                }
                return Encoding.UTF8.GetString(buffer, 0, end);
            }
            buffer[count++] = (byte)b;
        }
        return null;
    }

    private static void WriteLine(Stream s, string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text + "\n");
        try
        {
            s.Write(bytes, 0, bytes.Length);
            s.Flush();
        }
        catch (IOException)
        {

        }
    }

    private static bool Handle(string line, out string reply)
    {
        string trimmed = line.Trim();
        string[] parts = trimmed.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            reply = "err=empty_command";
            return false;
        }

        string verb = parts[0].ToLowerInvariant();
        switch (verb)
        {
            case "ping":
                reply = "pong";
                return false;

            case "get":

                reply = "value=" + Marshal.ReadInt32(_block, OffCounter).ToString(CultureInfo.InvariantCulture);
                return false;

            case "set":
            case "add":
            case "sub":
                reply = Arithmetic(verb, parts);
                return false;

            case "read":
                reply = Read(parts);
                return false;

            case "peek":
                reply = Peek(parts);
                return false;

            case "tick":
                reply = Tick(parts);
                return false;

            case "churn":
                reply = StartChurn(parts);
                return false;

            case "pause":
                _paused = true;
                reply = "paused=1";
                return false;

            case "resume":
                _paused = false;
                reply = "resumed=1";
                return false;

            case "protect":
                reply = Protect(parts);
                return false;

            case "externals":
                lock (Gate)
                {
                    reply = "external_changes=" + _externalChanges.ToString(CultureInfo.InvariantCulture) +
                        " last=" + _lastExternalValue.ToString(CultureInfo.InvariantCulture);
                }
                return false;

            case "chain":
                reply = Chain();
                return false;

            case "layout":
                reply = _startupJson;
                return false;

            case "exit":
                reply = "bye";
                return true;

            default:
                reply = "err=unknown_command";
                return false;
        }
    }

    private static string Arithmetic(string verb, string[] parts)
    {
        if (parts.Length != 2)
        {
            return "err=expected_one_argument";
        }
        long operand;
        if (!long.TryParse(parts[1], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out operand))
        {
            return "err=not_an_integer";
        }
        if (operand < int.MinValue || operand > int.MaxValue)
        {
            return "err=out_of_int32_range";
        }
        lock (Gate)
        {
            int current = Marshal.ReadInt32(_block, OffCounter);
            int next;
            if (verb == "set")
            {
                next = (int)operand;
            }
            else if (verb == "add")
            {
                next = unchecked(current + (int)operand);
            }
            else
            {
                next = unchecked(current - (int)operand);
            }
            Marshal.WriteInt32(_block, OffCounter, next);
            _lastSelfValue = next;
            return "value=" + next.ToString(CultureInfo.InvariantCulture);
        }
    }

    private static string Read(string[] parts)
    {
        if (parts.Length != 3)
        {
            return "err=expected_address_and_length";
        }
        ulong address;
        if (!TryParseHex(parts[1], out address))
        {
            return "err=not_a_hex_address";
        }
        int length;
        if (!int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out length)
            || length <= 0 || length > 256)
        {
            return "err=length_out_of_range";
        }

        Area area = FindReadableArea(address, length);
        if (area == null)
        {
            return "err=address_outside_readable_fixture_area";
        }
        byte[] copy = new byte[length];
        Marshal.Copy(new IntPtr(unchecked((long)address)), copy, 0, length);
        return "bytes=" + ToHex(copy) + " area=" + area.Name;
    }

    private static string Peek(string[] parts)
    {
        if (parts.Length != 2)
        {
            return "err=expected_area_name";
        }
        for (int i = 0; i < Areas.Count; i++)
        {
            if (Areas[i].Name == parts[1])
            {
                Area a = Areas[i];
                if (!a.Readable)
                {
                    return "err=area_is_deliberately_inaccessible";
                }
                int length = (int)Math.Min(a.Size, 256);
                byte[] copy = new byte[length];
                Marshal.Copy(a.Base, copy, 0, length);
                return "bytes=" + ToHex(copy) + " area=" + a.Name +
                    " base=0x" + ((ulong)a.Base.ToInt64()).ToString("x", CultureInfo.InvariantCulture);
            }
        }
        return "err=unknown_area";
    }

    private static string Tick(string[] parts)
    {
        if (parts.Length != 2)
        {
            return "err=expected_interval_ms";
        }
        int ms;
        if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out ms))
        {
            return "err=not_an_integer";
        }
        if (ms != 0 && (ms < 10 || ms > 10000))
        {
            return "err=interval_out_of_range";
        }
        _tickMs = ms;
        return "tick=" + ms.ToString(CultureInfo.InvariantCulture);
    }

    private static string Protect(string[] parts)
    {
        if (parts.Length != 2)
        {
            return "err=expected_protection_name";
        }
        uint requested;
        if (parts[1] == "noaccess")
        {
            requested = PAGE_NOACCESS;
        }
        else if (parts[1] == "rw" || parts[1] == "readwrite")
        {
            requested = PAGE_READWRITE;
        }
        else
        {
            return "err=unknown_protection";
        }
        uint previous;
        if (!VirtualProtect(_protect, new UIntPtr(PageSize), requested, out previous))
        {
            return "err=virtualprotect_failed_" +
                Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture);
        }
        for (int i = 0; i < Areas.Count; i++)
        {
            if (Areas[i].Name == "protect")
            {
                Areas[i].Readable = requested == PAGE_READWRITE;
            }
        }
        return "protect=" + parts[1] + " previous=0x" + previous.ToString("x", CultureInfo.InvariantCulture);
    }

    private static string Chain()
    {

        IntPtr root = Marshal.ReadIntPtr(_rootAddress);
        IntPtr n2 = root == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(root, OffNode1Next);
        IntPtr lf = n2 == IntPtr.Zero ? IntPtr.Zero : Marshal.ReadIntPtr(n2, OffNode2Next);
        int value = lf == IntPtr.Zero ? 0 : Marshal.ReadInt32(lf, OffLeafValue);
        return "root=" + Hex(_rootAddress) +
            " node1=" + Hex(root) +
            " node2=" + Hex(n2) +
            " leaf=" + Hex(lf) +
            " value=" + value.ToString(CultureInfo.InvariantCulture);
    }

    private static Area FindReadableArea(ulong address, int length)
    {
        for (int i = 0; i < Areas.Count; i++)
        {
            Area a = Areas[i];
            if (!a.Readable)
            {
                continue;
            }
            ulong start = (ulong)a.Base.ToInt64();
            ulong end = start + (ulong)a.Size;
            if (address >= start && address + (ulong)length <= end)
            {
                return a;
            }
        }
        return null;
    }

    private static bool TryParseHex(string text, out ulong value)
    {
        value = 0;
        string body = text;
        if (body.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            body = body.Substring(2);
        }
        return ulong.TryParse(body, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
    }

    private static string ToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.Length * 2);
        for (int i = 0; i < bytes.Length; i++)
        {
            sb.Append(bytes[i].ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    private static string Hex(IntPtr p)
    {
        return "0x" + ((ulong)p.ToInt64()).ToString("x", CultureInfo.InvariantCulture);
    }

    private static string J(string s)
    {
        StringBuilder sb = new StringBuilder(s.Length + 8);
        sb.Append('"');
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c == '"' || c == '\\')
            {
                sb.Append('\\').Append(c);
            }
            else if (c < 0x20)
            {
                sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            }
            else
            {
                sb.Append(c);
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    private static string Num(long v)
    {
        return v.ToString(CultureInfo.InvariantCulture);
    }

    private static string BuildStartupJson()
    {
        Process self = Process.GetCurrentProcess();
        bool wow64 = false;
        IsWow64Process(self.Handle, out wow64);

        StringBuilder sb = new StringBuilder(4096);
        sb.Append("{");
        sb.Append(J("fixture")).Append(":").Append(J("memscope")).Append(",");
        sb.Append(J("schema")).Append(":").Append(Num(1)).Append(",");
        sb.Append(J("pid")).Append(":").Append(Num(self.Id)).Append(",");
        sb.Append(J("arch")).Append(":").Append(J(IntPtr.Size == 8 ? "x64" : "x86")).Append(",");
        sb.Append(J("pointer_size")).Append(":").Append(Num(IntPtr.Size)).Append(",");
        sb.Append(J("wow64")).Append(":").Append(wow64 ? "true" : "false").Append(",");
        sb.Append(J("exe")).Append(":").Append(J(self.MainModule.FileName)).Append(",");
        sb.Append(J("pipe_name")).Append(":").Append(J(_pipeName)).Append(",");
        sb.Append(J("pipe_path")).Append(":").Append(J("\\\\.\\pipe\\" + _pipeName)).Append(",");

        sb.Append(J("areas")).Append(":{");
        for (int i = 0; i < Areas.Count; i++)
        {
            Area a = Areas[i];
            if (i > 0)
            {
                sb.Append(",");
            }
            sb.Append(J(a.Name)).Append(":{");
            sb.Append(J("address")).Append(":").Append(J(Hex(a.Base))).Append(",");
            sb.Append(J("size")).Append(":").Append(Num(a.Size)).Append(",");
            sb.Append(J("readable")).Append(":").Append(a.Readable ? "true" : "false").Append(",");
            sb.Append(J("note")).Append(":").Append(J(a.Note));
            sb.Append("}");
        }
        sb.Append("},");

        sb.Append(J("layout")).Append(":{");
        AppendLayout(sb);
        sb.Append("},");

        sb.Append(J("pointer_chain")).Append(":{");
        sb.Append(J("anchor_module")).Append(":").Append(J(AnchorDll)).Append(",");
        sb.Append(J("anchor_base")).Append(":").Append(J(Hex(_anchorBase))).Append(",");
        sb.Append(J("root_address")).Append(":").Append(J(Hex(_rootAddress))).Append(",");
        sb.Append(J("root_rva")).Append(":").Append(J("0x" +
            ((ulong)(_rootAddress.ToInt64() - _anchorBase.ToInt64()))
                .ToString("x", CultureInfo.InvariantCulture))).Append(",");
        sb.Append(J("deref_offsets")).Append(":[")
          .Append(Num(0)).Append(",").Append(Num(OffNode1Next)).Append(",").Append(Num(OffNode2Next))
          .Append("],");
        sb.Append(J("final_offset")).Append(":").Append(Num(OffLeafValue)).Append(",");
        sb.Append(J("node1")).Append(":").Append(J(Hex(_node1))).Append(",");
        sb.Append(J("node2")).Append(":").Append(J(Hex(_node2))).Append(",");
        sb.Append(J("leaf")).Append(":").Append(J(Hex(_leaf))).Append(",");
        sb.Append(J("leaf_value")).Append(":").Append(Num(LeafValue));
        sb.Append("},");

        sb.Append(J("datasets")).Append(":{");
        sb.Append(J("duplicate_value")).Append(":").Append(Num(DuplicateValue)).Append(",");
        sb.Append(J("duplicate_count")).Append(":").Append(Num(DuplicateCount)).Append(",");
        sb.Append(J("boundary_straddle_offset")).Append(":").Append(Num(BoundaryStraddleOffset)).Append(",");
        sb.Append(J("boundary_straddle_value")).Append(":").Append(Num(BoundaryStraddleValue)).Append(",");
        sb.Append(J("bench_enabled")).Append(":").Append(_bench != IntPtr.Zero ? "true" : "false").Append(",");
        sb.Append(J("bench_size")).Append(":").Append(Num(_benchSize)).Append(",");
        sb.Append(J("bench_value")).Append(":").Append(Num(BenchValue)).Append(",");
        sb.Append(J("bench_matches")).Append(":").Append(Num(_benchMatches));
        sb.Append("},");

        sb.Append(J("strings")).Append(":{");
        sb.Append(J("base")).Append(":").Append(J(Hex(_strings))).Append(",");
        sb.Append(J("utf8_terminated")).Append(":").Append(Num(OffUtf8Terminated)).Append(",");
        sb.Append(J("utf8_terminated_text")).Append(":").Append(J(Utf8Text)).Append(",");
        sb.Append(J("utf8_unterminated")).Append(":").Append(Num(OffUtf8Unterminated)).Append(",");
        sb.Append(J("utf8_unterminated_text")).Append(":").Append(J(Utf8UnterminatedText)).Append(",");
        sb.Append(J("utf8_invalid")).Append(":").Append(Num(OffUtf8Invalid)).Append(",");
        sb.Append(J("utf16_terminated")).Append(":").Append(Num(OffUtf16Terminated)).Append(",");
        sb.Append(J("utf16_terminated_text")).Append(":").Append(J(Utf16Text)).Append(",");
        sb.Append(J("utf16_unterminated")).Append(":").Append(Num(OffUtf16Unterminated)).Append(",");
        sb.Append(J("utf16_unterminated_text")).Append(":").Append(J(Utf16UnterminatedText)).Append(",");
        sb.Append(J("utf16_lone_surrogate")).Append(":").Append(Num(OffUtf16LoneSurrogate));
        sb.Append("}");

        sb.Append("}");
        return sb.ToString();
    }

    private static void AppendLayout(StringBuilder sb)
    {
        string[] names = {
            "sentinel_before", "counter", "sentinel_after",
            "i8_min", "i8_max", "u8_min", "u8_max",
            "i16_min", "i16_max", "u16_min", "u16_max",
            "i32_min", "i32_max", "u32_min", "u32_max",
            "i64_min", "i64_max", "u64_max",
            "f32_tenth", "f32_nan", "f32_pos_inf", "f32_neg_zero",
            "f64_tenth", "f64_neg_inf", "f64_nan",
            "pointer_root", "pointer_guard_after", "scratch", "scratch_size", "block_size"
        };
        int[] values = {
            OffSentinelBefore, OffCounter, OffSentinelAfter,
            OffI8Min, OffI8Max, OffU8Min, OffU8Max,
            OffI16Min, OffI16Max, OffU16Min, OffU16Max,
            OffI32Min, OffI32Max, OffU32Min, OffU32Max,
            OffI64Min, OffI64Max, OffU64Max,
            OffF32Tenth, OffF32Nan, OffF32PosInf, OffF32NegZero,
            OffF64Tenth, OffF64NegInf, OffF64Nan,
            OffPointerRoot, OffPointerRoot + IntPtr.Size, OffScratch, ScratchSize, BlockSize
        };
        for (int i = 0; i < names.Length; i++)
        {
            if (i > 0)
            {
                sb.Append(",");
            }
            sb.Append(J(names[i])).Append(":").Append(Num(values[i]));
        }
    }
}
