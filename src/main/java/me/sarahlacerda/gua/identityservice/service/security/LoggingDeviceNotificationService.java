package me.sarahlacerda.gua.identityservice.service.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

@Component
@Primary
@Slf4j
public class LoggingDeviceNotificationService implements DeviceNotificationService {

    @Override
    public void notifyNewDevice(String userId, String deviceId, TrustedDeviceService.DeviceMetadata metadata) {
        log.info("New device detected for {} (deviceId={} platform={} appVersion={} name={})",
            userId,
            deviceId,
            metadata.platform(),
            metadata.appVersion(),
            metadata.deviceName());
    }

    @Override
    public void notifyPhoneChangeInitiated(String userId, String maskedOldPhone, String maskedNewPhone) {
        log.info("Phone change initiated for {} (old={} new={}) — alerting old number", userId, maskedOldPhone,
            maskedNewPhone);
    }

    @Override
    public void notifyPhoneChanged(String userId, String maskedNewPhone) {
        log.info("Phone changed for {} (new={}) — alerting account owner", userId, maskedNewPhone);
    }
}
