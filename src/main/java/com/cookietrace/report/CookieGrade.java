package com.cookietrace.report;

/**
 * Letter grade representing the security posture of session cookies.
 *
 * Grading Scale:
 * - A: Score >= 90 (Strong security: Secure, HttpOnly, and Strict/Lax SameSite)
 * - B: Score >= 70 (Good security)
 * - C: Score >= 50 (Fair security, minor flags missing)
 * - D: Score >= 30 (Poor security, high exposure)
 * - F: Score < 30  (Vulnerable: unencrypted, script-accessible, or cross-site enabled)
 */
public enum CookieGrade {
    A,
    B,
    C,
    D,
    F
}
