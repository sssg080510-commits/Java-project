package com.cookietrace.exception;

/**
 * Custom runtime exception thrown when session data or threat alerts fail validation.
 *
 * Why RuntimeException?
 * It represents an unchecked exception, meaning caller code is not forced to declare it in a
 * 'throws' clause, but can catch it when handling invalid or untrusted input (such as corrupted CSV lines).
 */
public class InvalidSessionDataException extends RuntimeException {

    /**
     * Constructs a new InvalidSessionDataException with the specified error message.
     *
     * @param message Description of the validation failure
     */
    public InvalidSessionDataException(String message) {
        super(message);
    }
}
