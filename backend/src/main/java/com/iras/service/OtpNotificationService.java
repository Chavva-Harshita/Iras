package com.iras.service;

import com.iras.entity.OtpPurpose;

public interface OtpNotificationService {
    void sendOtp(String recipient, String otpCode, OtpPurpose purpose);
}
