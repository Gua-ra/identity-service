package me.sarahlacerda.gua.identityservice.service.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import me.sarahlacerda.gua.identityservice.domain.TrustedDevice;
import me.sarahlacerda.gua.identityservice.repository.TrustedDeviceRepository;
import me.sarahlacerda.gua.identityservice.service.security.TrustedDeviceService.DeviceMetadata;

@ExtendWith(MockitoExtension.class)
class TrustedDeviceServiceTest {

    @Mock
    private TrustedDeviceRepository repository;

    private TrustedDeviceService service;

    @BeforeEach
    void setUp() {
        service = new TrustedDeviceService(repository);
    }

    @Test
    void registerDeviceCreatesNewRecordWhenMissing() {
        DeviceMetadata metadata = metadata();
        when(repository.findByUserIdAndDeviceId("@user:gua.global", "device-1")).thenReturn(Optional.empty());

        boolean created = service.registerDevice("@user:gua.global", "device-1", metadata);

        assertThat(created).isTrue();
        ArgumentCaptor<TrustedDevice> captor = ArgumentCaptor.forClass(TrustedDevice.class);
        verify(repository).save(captor.capture());
        TrustedDevice saved = captor.getValue();
        assertThat(saved.getUserId()).isEqualTo("@user:gua.global");
        assertThat(saved.getDeviceId()).isEqualTo("device-1");
        assertThat(saved.getDeviceName()).isEqualTo(metadata.deviceName());
        assertThat(saved.getPlatform()).isEqualTo(metadata.platform());
        assertThat(saved.getAppVersion()).isEqualTo(metadata.appVersion());
        assertThat(saved.getLastIp()).isEqualTo(metadata.ipAddress());
    }

    @Test
    void registerDeviceTouchesExistingRecord() {
        DeviceMetadata metadata = metadata();
        TrustedDevice existing = TrustedDevice.builder()
            .userId("@user:gua.global")
            .deviceId("device-1")
            .deviceName("Old")
            .platform("OldOS")
            .appVersion("0.9")
            .lastIp("192.168.0.10")
            .build();
        when(repository.findByUserIdAndDeviceId("@user:gua.global", "device-1")).thenReturn(Optional.of(existing));

        boolean created = service.registerDevice("@user:gua.global", "device-1", metadata);

        assertThat(created).isFalse();
        assertThat(existing.getDeviceName()).isEqualTo(metadata.deviceName());
        assertThat(existing.getPlatform()).isEqualTo(metadata.platform());
        assertThat(existing.getAppVersion()).isEqualTo(metadata.appVersion());
        assertThat(existing.getLastIp()).isEqualTo(metadata.ipAddress());
        verify(repository, never()).save(any());
    }

    private DeviceMetadata metadata() {
        return DeviceMetadata.builder()
            .deviceName("Pixel")
            .platform("Android")
            .appVersion("14.0")
            .ipAddress("100.64.0.1")
            .build();
    }
}
