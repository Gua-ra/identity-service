package me.sarahlacerda.gua.identityservice.service.security;

public interface DeviceNotificationService {
    void notifyNewDevice(String userId, String deviceId, TrustedDeviceService.DeviceMetadata metadata);
}
