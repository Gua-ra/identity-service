package me.sarahlacerda.gua.identityservice.service.security;

import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import me.sarahlacerda.gua.identityservice.domain.TrustedDevice;
import me.sarahlacerda.gua.identityservice.repository.TrustedDeviceRepository;

@Service
@RequiredArgsConstructor
public class TrustedDeviceService {

    private final TrustedDeviceRepository repository;

    @Transactional
    public boolean registerDevice(String userId, String deviceId, DeviceMetadata metadata) {
        return repository.findByUserIdAndDeviceId(userId, deviceId)
            .map(existing -> updateExisting(existing, metadata))
            .orElseGet(() -> createNew(userId, deviceId, metadata));
    }

    private boolean updateExisting(TrustedDevice device, DeviceMetadata metadata) {
        device.touch(metadata.deviceName(), metadata.platform(), metadata.appVersion(), metadata.ipAddress());
        return false;
    }

    private boolean createNew(String userId, String deviceId, DeviceMetadata metadata) {
        TrustedDevice device = TrustedDevice.builder()
            .userId(userId)
            .deviceId(deviceId)
            .deviceName(metadata.deviceName())
            .platform(metadata.platform())
            .appVersion(metadata.appVersion())
            .lastIp(metadata.ipAddress())
            .build();
        repository.save(device);
        return true;
    }

    @Builder(toBuilder = true)
    public record DeviceMetadata(String deviceName, String platform, String appVersion, String ipAddress) { }
}
