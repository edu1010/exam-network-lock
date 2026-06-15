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

    private readonly object _gate = new();
    private System.Threading.Timer? _beepTimer;
    private bool _alarming;

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
            _beepTimer = new System.Threading.Timer(_ => SafeBeep(), null, 0, 1500);
        }
    }

    public void StopAlarm()
    {
        lock (_gate)
        {
            _alarming = false;
            _beepTimer?.Dispose();
            _beepTimer = null;
        }
    }

    private static void PressKey(byte vk)
    {
        keybd_event(vk, 0, 0, UIntPtr.Zero);
        keybd_event(vk, 0, KeyEventFKeyUp, UIntPtr.Zero);
    }

    private static void SafeBeep()
    {
        try
        {
            Console.Beep(1000, 600);
        }
        catch
        {
            // Console.Beep can fail on some configurations; ignore.
        }
    }

    public void Dispose()
    {
        StopAlarm();
    }
}
