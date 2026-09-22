package com.iras.service;

import com.iras.entity.OtpPurpose;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ConsoleOtpNotificationService implements OtpNotificationService {

    private static final Logger log = LoggerFactory.getLogger(ConsoleOtpNotificationService.class);

    @Override
    public void sendOtp(String recipient, String otpCode, OtpPurpose purpose) {
        log.info("==========================================================");
        log.info("[DEV OTP] Verification code for {} [{}]: {}", recipient, purpose, otpCode);
        log.info("==========================================================");
    }
}
