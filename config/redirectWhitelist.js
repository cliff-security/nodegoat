/**
 * Redirect Whitelist Configuration
 * 
 * This file defines which external domains the application is allowed to redirect to.
 * Add any safe external domains here to prevent open redirect vulnerabilities.
 * 
 * For internal redirects (relative URLs starting with /), validation will always allow them.
 * Only absolute URLs are checked against this whitelist.
 */

const ALLOWED_REDIRECT_DOMAINS = {
    // Internal redirects (relative paths) are always allowed
    // Examples: "/dashboard", "/profile", "../../settings"
    
    // External domains - Add approved domains here
    // Be conservative: only add domains you fully control or trust
    // Examples:
    // "trusted-partner.com",
    // "www.trusted-partner.com",
    // "learning.example.com"
};

// Convert to array for easier use
const allowedDomainsList = Object.keys(ALLOWED_REDIRECT_DOMAINS);

// Add environment-specific domains if needed
if (process.env.NODE_ENV === "development") {
    // Add development domains
    allowedDomainsList.push("localhost");
    allowedDomainsList.push("127.0.0.1");
}

module.exports = {
    // Array of allowed domains for external redirects
    allowedDomains: allowedDomainsList,
    
    // Original configuration object for reference
    domainConfig: ALLOWED_REDIRECT_DOMAINS,
    
    /**
     * Add a domain to the whitelist
     * @param {string} domain - Domain to add
     */
    addDomain: (domain) => {
        if (domain && !allowedDomainsList.includes(domain)) {
            allowedDomainsList.push(domain);
        }
    },
    
    /**
     * Remove a domain from the whitelist
     * @param {string} domain - Domain to remove
     */
    removeDomain: (domain) => {
        const index = allowedDomainsList.indexOf(domain);
        if (index > -1) {
            allowedDomainsList.splice(index, 1);
        }
    },
    
    /**
     * Check if a domain is whitelisted
     * @param {string} domain - Domain to check
     * @returns {boolean} True if domain is whitelisted
     */
    isDomainAllowed: (domain) => {
        return allowedDomainsList.includes(domain);
    },
    
    /**
     * Get all whitelisted domains
     * @returns {Array<string>} List of allowed domains
     */
    getAllowedDomains: () => {
        return [...allowedDomainsList];
    }
};
