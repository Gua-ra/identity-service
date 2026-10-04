package me.sarahlacerda.gua.identityservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import me.sarahlacerda.gua.identityservice.domain.TrustedDevice;

public interface TrustedDeviceRepository extends JpaRepository<TrustedDevice, UUID> {
    Optional<TrustedDevice> findByUserIdAndDeviceId(String userId, String deviceId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("delete from TrustedDevice d where d.userId = :userId")
    int deleteAllByUserId(@Param("userId") String userId);
}
