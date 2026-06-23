package me.sarahlacerda.gua.identityservice.service.security;

public interface DeviceNotificationService {
    void notifyNewDevice(String userId, String deviceId, TrustedDeviceService.DeviceMetadata metadata);

    /**
     * Out-of-band alert sent when a phone-number change is <em>initiated</em>. Sent
     * to the OLD number so a victim of session/SIM-swap takeover sees the attempt
     * while the OTP-to-new-number leg is still pending.
     */
    void notifyPhoneChangeInitiated(String userId, String maskedOldPhone, String maskedNewPhone);

    /**
     * Out-of-band alert sent when a phone-number change <em>completes</em>. Sent so
     * the account owner is notified the linked number is now the new value.
     */
    void notifyPhoneChanged(String userId, String maskedNewPhone);
}
