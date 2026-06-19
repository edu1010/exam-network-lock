using ExamLockClient.Core.Platform;

namespace ExamLockClient.Core.Monitoring;

/// <summary>Alarm sound shape: a continuous repeating tone, or a short three-beep burst.</summary>
public enum BeepPattern
{
    Continuous,
    ThreeBeeps
}

/// <summary>
/// Raises the speaker volume and emits an audible alarm. The actual tone and volume change are
/// delegated to <see cref="IPlatform"/> (Console.Beep + Core Audio on Windows; a generated WAV via
/// paplay + pactl on Linux), so the cadence logic here is shared.
/// </summary>
public sealed class AudioAlerter : IDisposable
{
    // Continuous tone: a long beep with a short gap, repeated until acknowledged.
    private const int BeepFrequency = 1000;
    private const int BeepDurationMs = 1500;
    private const int BeepGapMs = 250;

    // Three-beep burst: three short beeps, then silence (one burst per incident).
    private const int PulseFrequency = 1000;
    private const int PulseDurationMs = 220;
    private const int PulseGapMs = 180;

    private readonly IPlatform _platform;
    private readonly object _gate = new();
    private Thread? _beepThread;
    private volatile bool _alarming;

    public BeepPattern Pattern { get; set; } = BeepPattern.Continuous;

    public int VolumePercent { get; set; } = 100;

    public AudioAlerter(IPlatform platform)
    {
        _platform = platform;
    }

    public void RaiseVolume()
    {
        _platform.TrySetVolume(Math.Clamp(VolumePercent, 0, 100));
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
                _platform.Beep(PulseFrequency, PulseDurationMs);
                if (i < 2 && _alarming)
                {
                    Thread.Sleep(PulseGapMs);
                }
            }

            _alarming = false;
            return;
        }

        while (_alarming)
        {
            _platform.Beep(BeepFrequency, BeepDurationMs);
            if (!_alarming)
            {
                break;
            }

            Thread.Sleep(BeepGapMs);
        }
    }

    public void Dispose()
    {
        StopAlarm();
    }
}
