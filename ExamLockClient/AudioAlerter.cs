using System.Runtime.InteropServices;

namespace ExamLockClient;

/// <summary>
/// Raises the speaker volume to maximum and emits a repeating audible alarm.
/// Volume is raised dependency-free by simulating many VK_VOLUME_UP key presses.
/// </summary>
public sealed class AudioAlerter : IDisposable
{
    private const byte VkVolumeUp = 0xAF;
    private const uint KeyEventFKeyUp = 0x0002;

    [DllImport("user32.dll")]
    private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, UIntPtr dwExtraInfo);

    // Alarm tone: a long beep with a short gap, repeated until acknowledged.
    private const int BeepFrequency = 1000;   // Hz
    private const int BeepDurationMs = 1500;  // length of each beep
    private const int BeepGapMs = 250;        // silence between beeps

    private readonly object _gate = new();
    private Thread? _beepThread;
    private volatile bool _alarming;

    public void RaiseVolumeToMax()
    {
        try
        {
            // Unmute first (mute is a toggle; press it only if currently muted is unknown,
            // so we send volume-up which also unmutes on most drivers).
            for (var i = 0; i < 60; i++)
            {
                PressKey(VkVolumeUp);
            }
        }
        catch
        {
            // Best-effort; ignore failures.
        }
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
        while (_alarming)
        {
            try
            {
                Console.Beep(BeepFrequency, BeepDurationMs);
            }
            catch
            {
                // Console.Beep can fail on some configurations; ignore.
            }

            if (!_alarming)
            {
                break;
            }

            Thread.Sleep(BeepGapMs);
        }
    }

    private static void PressKey(byte vk)
    {
        keybd_event(vk, 0, 0, UIntPtr.Zero);
        keybd_event(vk, 0, KeyEventFKeyUp, UIntPtr.Zero);
    }

    public void Dispose()
    {
        StopAlarm();
    }
}
