package com.cookietrace.model;

/**
 * Enumeration representing the severity level of a threat alert.
 * Using an enum restricts the severity to predefined valid values (LOW, MEDIUM, HIGH)
 * preventing arbitrary invalid strings.
 */
public enum RiskLevel {
    LOW,
    MEDIUM,
    HIGH
}
