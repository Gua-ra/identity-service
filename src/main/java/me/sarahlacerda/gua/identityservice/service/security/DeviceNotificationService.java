package me.sarahlacerda.gua.identityservice.service.security;

public interface DeviceNotificationService {
    void notifyNewDevice(String userId, String deviceId, TrustedDeviceService.DeviceMetadata metadata);

    /**
     * Out-of-band alert sent when a phone-number change is initiated. Sent to the old number so the
     * account owner sees a takeover attempt while the new-number OTP is still pending.
     */
    void notifyPhoneChangeInitiated(String userId, String maskedOldPhone, String maskedNewPhone);

    /** Out-of-band alert sent when a phone-number change completes. */
    void notifyPhoneChanged(String userId, String maskedNewPhone);
}
