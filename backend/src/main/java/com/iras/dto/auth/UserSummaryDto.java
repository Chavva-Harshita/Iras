package com.iras.dto.auth;

import com.iras.entity.User;

public record UserSummaryDto(
        Long id,
        String email,
        String firstName,
        String lastName,
        String phone,
        String role,
        boolean isVerified
) {
    public static UserSummaryDto fromEntity(User user) {
        return new UserSummaryDto(
                user.getId(),
                user.getEmail(),
                user.getFirstName(),
                user.getLastName(),
                user.getPhone(),
                user.getRole(),
                user.isVerified()
        );
    }
}
