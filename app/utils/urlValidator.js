/**
 * URL Validation Utility
 * Prevents open redirect attacks by validating redirect URLs against an allow-list
 */

const url = require("url");

/**
 * Configuration for allowed redirect domains
 * Add safe domains that the application is allowed to redirect to
 */
const ALLOWED_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "example.com",
    "www.example.com"
];

/**
 * Validates if a URL is safe to redirect to
 * 
 * @param {string} redirectUrl - The URL to validate
 * @param {Array<string>} allowedDomains - Array of allowed domains (optional, uses ALLOWED_DOMAINS if not provided)
 * @returns {Object} { isValid: boolean, url: string, error: string|null }
 */
const validateRedirectUrl = (redirectUrl, allowedDomains = ALLOWED_DOMAINS) => {
    const result = {
        isValid: false,
        url: null,
        error: null
    };

    // Check if URL is provided
    if (!redirectUrl || typeof redirectUrl !== "string") {
        result.error = "Redirect URL is required and must be a string";
        return result;
    }

    // Trim whitespace
    const trimmedUrl = redirectUrl.trim();

    if (!trimmedUrl) {
        result.error = "Redirect URL cannot be empty";
        return result;
    }

    try {
        // Parse the URL
        const parsedUrl = url.parse(trimmedUrl);
        
        // Allow relative URLs (internal redirects)
        if (!parsedUrl.hostname) {
            // This is a relative URL (e.g., "/dashboard", "../profile")
            // Ensure it starts with / to prevent protocol-relative URLs like //evil.com
            if (trimmedUrl.startsWith("/")) {
                result.isValid = true;
                result.url = trimmedUrl;
                return result;
            } else if (!trimmedUrl.includes("://") && !trimmedUrl.startsWith("//")) {
                // Allow relative paths without leading slash but no protocol
                result.isValid = true;
                result.url = trimmedUrl;
                return result;
            } else {
                result.error = "Protocol-relative URLs are not allowed";
                return result;
            }
        }

        // For absolute URLs, validate the hostname against the allow-list
        const hostname = parsedUrl.hostname || parsedUrl.host;
        
        const isAllowed = allowedDomains.some(domain => {
            // Exact match or subdomain match
            return hostname === domain || hostname.endsWith("." + domain);
        });

        if (!isAllowed) {
            result.error = `Redirect to '${hostname}' is not allowed. Only the following domains are permitted: ${allowedDomains.join(", ")}`;
            return result;
        }

        // Validate the protocol is safe
        const protocol = parsedUrl.protocol;
        if (protocol && !["http:", "https:"].includes(protocol)) {
            result.error = `Protocol '${protocol}' is not allowed. Only http and https are permitted`;
            return result;
        }

        result.isValid = true;
        result.url = trimmedUrl;
        return result;
    } catch (error) {
        result.error = `Invalid URL format: ${error.message}`;
        return result;
    }
};

/**
 * Safely redirect with URL validation
 * Logs rejected redirects for security monitoring
 * 
 * @param {Object} res - Express response object
 * @param {string} redirectUrl - The URL to redirect to
 * @param {Function} logger - Optional logger function for security events
 * @param {Array<string>} allowedDomains - Array of allowed domains (optional)
 */
const safeRedirect = (res, redirectUrl, logger = null, allowedDomains = ALLOWED_DOMAINS) => {
    const validation = validateRedirectUrl(redirectUrl, allowedDomains);

    if (!validation.isValid) {
        // Log the rejected redirect attempt for security monitoring
        const logMessage = `Redirect blocked: ${validation.error} (Requested URL: ${redirectUrl})`;
        
        if (logger && typeof logger === "function") {
            logger(logMessage);
        } else {
            console.warn(`[SECURITY] ${logMessage}`);
        }

        // Return 400 Bad Request instead of redirecting
        return res.status(400).send({
            error: "Invalid redirect URL",
            message: "The requested redirect destination is not allowed"
        });
    }

    // Safe to redirect
    return res.redirect(validation.url);
};

/**
 * Get or set the allowed domains configuration
 * 
 * @param {Array<string>} domains - Array of domains to set (optional)
 * @returns {Array<string>} Current allowed domains
 */
const getAllowedDomains = (domains = null) => {
    if (domains && Array.isArray(domains)) {
        ALLOWED_DOMAINS.length = 0;
        ALLOWED_DOMAINS.push(...domains);
    }
    return ALLOWED_DOMAINS;
};

module.exports = {
    validateRedirectUrl,
    safeRedirect,
    getAllowedDomains
};
