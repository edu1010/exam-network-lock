using Windows.Devices.Radios;

namespace ExamLockClient;

/// <summary>
/// Best-effort control of the Bluetooth radio via the WinRT Radios API.
/// Any failure (unsupported hardware, denied access) is reported, never thrown.
/// </summary>
public sealed class RadioService
{
    public async Task<(bool ok, string error)> SetBluetoothAsync(bool on)
    {
        try
        {
            var access = await Radio.RequestAccessAsync();
            if (access != RadioAccessStatus.Allowed)
            {
                return (false, $"Radio access not allowed: {access}");
            }

            var radios = await Radio.GetRadiosAsync();
            var bluetooth = radios.Where(r => r.Kind == RadioKind.Bluetooth).ToList();
            if (bluetooth.Count == 0)
            {
                return (false, "No Bluetooth radio found.");
            }

            var target = on ? RadioState.On : RadioState.Off;
            var allOk = true;
            string lastError = string.Empty;
            foreach (var radio in bluetooth)
            {
                var status = await radio.SetStateAsync(target);
                if (status != RadioAccessStatus.Allowed)
                {
                    allOk = false;
                    lastError = $"SetState returned {status}.";
                }
            }

            return (allOk, lastError);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
