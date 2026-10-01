package me.sarahlacerda.gua.identityservice.service.security;

public interface DeviceNotificationService {
    void notifyNewDevice(String userId, String deviceId, TrustedDeviceService.DeviceMetadata metadata);

    /** Sent to the old number so the account owner sees a takeover attempt while it is still pending. */
    void notifyPhoneChangeInitiated(String userId, String maskedOldPhone, String maskedNewPhone);

    void notifyPhoneChanged(String userId, String maskedNewPhone);
}
