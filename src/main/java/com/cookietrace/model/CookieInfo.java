package com.cookietrace.model;

import com.cookietrace.exception.InvalidSessionDataException;

/**
 * Represents cookie security attributes associated with a web session event.
 *
 * Encapsulation Design:
 * - All fields are marked 'private final' so internal state cannot be modified from outside
 *   after the object is instantiated (immutability).
 * - There are NO setters. Once created through the constructor, the cookie data is guaranteed
 *   to remain valid, preventing external code from accidentally corrupting the security flags.
 * - Getters provide safe, read-only access to the internal fields.
 */
public class CookieInfo {

    // Private final fields to enforce encapsulation and immutability
    private final boolean secure;
    private final boolean httpOnly;
    private final String sameSite;

    /**
     * Constructs and validates a CookieInfo instance.
     *
     * @param secure   Whether the Secure cookie flag is present (HTTPS only)
     * @param httpOnly Whether the HttpOnly cookie flag is present (blocks JavaScript access)
     * @param sameSite The SameSite policy (must be Strict, Lax, or None)
     * @throws InvalidSessionDataException If sameSite is null or not Strict, Lax, or None
     */
    public CookieInfo(boolean secure, boolean httpOnly, String sameSite) {
        this.secure = secure;
        this.httpOnly = httpOnly;

        // Validation for sameSite attribute
        if (sameSite == null || sameSite.trim().isEmpty()) {
            throw new InvalidSessionDataException("sameSite attribute cannot be null or empty.");
        }

        String normalized = sameSite.trim();
        if (normalized.equalsIgnoreCase("Strict")) {
            this.sameSite = "Strict";
        } else if (normalized.equalsIgnoreCase("Lax")) {
            this.sameSite = "Lax";
        } else if (normalized.equalsIgnoreCase("None")) {
            this.sameSite = "None";
        } else {
            throw new InvalidSessionDataException(
                "Invalid sameSite attribute: '" + sameSite + "'. Expected one of: Strict, Lax, None."
            );
        }
    }

    // Read-only getters (no setters allowed to ensure encapsulation)

    public boolean isSecure() {
        return secure;
    }

    public boolean isHttpOnly() {
        return httpOnly;
    }

    public String getSameSite() {
        return sameSite;
    }

    @Override
    public String toString() {
        return "CookieInfo[secure=" + secure + ", httpOnly=" + httpOnly + ", sameSite=" + sameSite + "]";
    }
}
