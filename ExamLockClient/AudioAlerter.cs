using System.Runtime.InteropServices;

namespace ExamLockClient;

/// <summary>Alarm sound shape: a continuous repeating tone, or a short three-beep burst.</summary>
public enum BeepPattern
{
    Continuous,
    ThreeBeeps
}

/// <summary>
/// Raises the speaker volume to a configured level and emits an audible alarm.
/// Volume is set via the Core Audio endpoint (absolute level); if that fails it falls back
/// to simulating VK_VOLUME_UP/DOWN key presses so the alarm is still audible.
/// </summary>
public sealed class AudioAlerter : IDisposable
{
    private const byte VkVolumeUp = 0xAF;
    private const byte VkVolumeDown = 0xAE;
    private const uint KeyEventFKeyUp = 0x0002;

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    // Continuous tone: a long beep with a short gap, repeated until acknowledged.
    private const int BeepFrequency = 1000;   // Hz
    private const int BeepDurationMs = 1500;  // length of each beep
    private const int BeepGapMs = 250;        // silence between beeps

    // Three-beep burst: three short beeps, then silence (one burst per incident).
    private const int PulseFrequency = 1000;  // Hz
    private const int PulseDurationMs = 220;   // length of each short beep
    private const int PulseGapMs = 180;        // silence between the short beeps

    private readonly object _gate = new();
    private Thread? _beepThread;
    private volatile bool _alarming;

    /// <summary>Alarm shape (continuous vs three beeps). Read by the beep thread.</summary>
    public BeepPattern Pattern { get; set; } = BeepPattern.Continuous;

    /// <summary>Speaker level (0–100) the alarm raises the volume to.</summary>
    public int VolumePercent { get; set; } = 100;

    public void RaiseVolume()
    {
        var percent = Math.Clamp(VolumePercent, 0, 100);
        if (TrySetVolumeViaCoreAudio(percent))
        {
            return;
        }

        RaiseVolumeViaKeys(percent);
    }

    public void StartAlarm()
    {
        lock (_gate)
        {
            if (_alarming)
            {
                return;
            }

            _alarming = true;
            _beepThread = new Thread(BeepLoop) { IsBackground = true };
            _beepThread.Start();
        }
    }

    public void StopAlarm()
    {
        lock (_gate)
        {
            _alarming = false;
            _beepThread = null;
        }
    }

    private void BeepLoop()
    {
        if (Pattern == BeepPattern.ThreeBeeps)
        {
            for (var i = 0; i < 3 && _alarming; i++)
            {
                SafeBeep(PulseFrequency, PulseDurationMs);
                if (i < 2 && _alarming)
                {
                    Thread.Sleep(PulseGapMs);
                }
            }

            // A burst is a finite alert; release the thread so the next incident can fire again.
            _alarming = false;
            return;
        }

        while (_alarming)
        {
            SafeBeep(BeepFrequency, BeepDurationMs);
            if (!_alarming)
            {
                break;
            }

            Thread.Sleep(BeepGapMs);
        }
    }

    private static void SafeBeep(int frequency, int durationMs)
    {
        try
        {
            Console.Beep(frequency, durationMs);
        }
        catch
        {
            // Console.Beep can fail on some configurations; ignore.
        }
    }

    private void RaiseVolumeViaKeys(int percent)
    {
        try
        {
            // Drive the level to a known baseline (0), then step up. Each VK_VOLUME_UP
            // step is ~2%, so ~50 presses span the full range.
            for (var i = 0; i < 60; i++)
            {
                PressKey(VkVolumeDown);
            }

            var ups = (int)Math.Round(percent / 2.0);
            for (var i = 0; i < ups; i++)
            {
                PressKey(VkVolumeUp);
            }
        }
        catch
        {
            // Best-effort; ignore failures.
        }
    }

    private static void PressKey(byte vk)
    {
        keybd_event(vk, 0, 0, UIntPtr.Zero);
        keybd_event(vk, 0, KeyEventFKeyUp, UIntPtr.Zero);
    }

    // ----- Core Audio (absolute master volume) -----

    private static bool TrySetVolumeViaCoreAudio(int percent)
    {
        IMMDeviceEnumerator? enumerator = null;
        IMMDevice? device = null;
        IAudioEndpointVolume? volume = null;
        try
        {
            enumerator = (IMMDeviceEnumerator)new MMDeviceEnumerator();
            if (enumerator.GetDefaultAudioEndpoint(0 /* eRender */, 1 /* eMultimedia */, out device) != 0 || device is null)
            {
                return false;
            }

            var iid = typeof(IAudioEndpointVolume).GUID;
            if (device.Activate(ref iid, 1 /* CLSCTX_INPROC_SERVER */, IntPtr.Zero, out var obj) != 0 || obj is not IAudioEndpointVolume v)
            {
                return false;
            }

            volume = v;
            var ctx = Guid.Empty;
            volume.SetMute(false, ref ctx);
            return volume.SetMasterVolumeLevelScalar(Math.Clamp(percent, 0, 100) / 100f, ref ctx) == 0;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (volume is not null) Marshal.ReleaseComObject(volume);
            if (device is not null) Marshal.ReleaseComObject(device);
            if (enumerator is not null) Marshal.ReleaseComObject(enumerator);
        }
    }

    [ComImport, Guid("BCDE0395-E52F-467C-8E3D-C4579291692E")]
    private class MMDeviceEnumerator
    {
    }

    [ComImport, Guid("A95664D2-9614-4F35-A746-DE8DB63617E6"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDeviceEnumerator
    {
        [PreserveSig] int EnumAudioEndpoints(int dataFlow, int stateMask, out IntPtr devices);
        [PreserveSig] int GetDefaultAudioEndpoint(int dataFlow, int role, out IMMDevice? device);
    }

    [ComImport, Guid("D666063F-1587-4E43-81F1-B948E807363F"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IMMDevice
    {
        [PreserveSig] int Activate(ref Guid iid, int clsCtx, IntPtr activationParams,
            [MarshalAs(UnmanagedType.IUnknown)] out object iface);
    }

    [ComImport, Guid("5CDF2C82-841E-4546-9722-0CF74078229A"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IAudioEndpointVolume
    {
        [PreserveSig] int RegisterControlChangeNotify(IntPtr notify);                       // 1
        [PreserveSig] int UnregisterControlChangeNotify(IntPtr notify);                     // 2
        [PreserveSig] int GetChannelCount(out int count);                                   // 3
        [PreserveSig] int SetMasterVolumeLevel(float levelDb, ref Guid eventContext);        // 4
        [PreserveSig] int SetMasterVolumeLevelScalar(float level, ref Guid eventContext);    // 5
        [PreserveSig] int GetMasterVolumeLevel(out float levelDb);                          // 6
        [PreserveSig] int GetMasterVolumeLevelScalar(out float level);                      // 7
        [PreserveSig] int SetChannelVolumeLevel(uint channel, float levelDb, ref Guid ctx);  // 8
        [PreserveSig] int SetChannelVolumeLevelScalar(uint channel, float level, ref Guid ctx); // 9
        [PreserveSig] int GetChannelVolumeLevel(uint channel, out float levelDb);           // 10
        [PreserveSig] int GetChannelVolumeLevelScalar(uint channel, out float level);       // 11
        [PreserveSig] int SetMute([MarshalAs(UnmanagedType.Bool)] bool mute, ref Guid eventContext); // 12
    }

    public void Dispose()
    {
        StopAlarm();
    }
}
