/**
 * Unit tests for URL Validator utility
 * Tests the validateRedirectUrl function with various attack scenarios
 */

const should = require("should");
const { validateRedirectUrl, safeRedirect } = require("../app/utils/urlValidator");

describe("URL Validator - validateRedirectUrl", () => {
    const testAllowedDomains = ["example.com", "www.example.com", "trusted.org"];

    describe("Valid redirects - relative URLs", () => {
        it("should allow relative URLs starting with /", () => {
            const result = validateRedirectUrl("/dashboard", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("/dashboard");
            should.not.exist(result.error);
        });

        it("should allow nested relative paths", () => {
            const result = validateRedirectUrl("/user/profile/edit", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("/user/profile/edit");
            should.not.exist(result.error);
        });

        it("should allow relative paths with query strings", () => {
            const result = validateRedirectUrl("/dashboard?id=123&name=test", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("/dashboard?id=123&name=test");
            should.not.exist(result.error);
        });

        it("should allow relative paths with fragments", () => {
            const result = validateRedirectUrl("/docs#section-1", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("/docs#section-1");
            should.not.exist(result.error);
        });

        it("should allow parent directory relative paths", () => {
            const result = validateRedirectUrl("../profile", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("../profile");
            should.not.exist(result.error);
        });

        it("should allow multiple parent directory traversals", () => {
            const result = validateRedirectUrl("../../settings", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("../../settings");
            should.not.exist(result.error);
        });
    });

    describe("Valid redirects - whitelisted absolute URLs", () => {
        it("should allow http URLs to whitelisted domains", () => {
            const result = validateRedirectUrl("http://example.com/learn", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("http://example.com/learn");
            should.not.exist(result.error);
        });

        it("should allow https URLs to whitelisted domains", () => {
            const result = validateRedirectUrl("https://www.example.com/courses", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("https://www.example.com/courses");
            should.not.exist(result.error);
        });

        it("should allow trusted domain", () => {
            const result = validateRedirectUrl("https://trusted.org/resource", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("https://trusted.org/resource");
            should.not.exist(result.error);
        });

        it("should allow subdomains of whitelisted domains", () => {
            const result = validateRedirectUrl("https://api.example.com/docs", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("https://api.example.com/docs");
            should.not.exist(result.error);
        });

        it("should allow deeply nested subdomains", () => {
            const result = validateRedirectUrl("https://v1.api.example.com/data", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("https://v1.api.example.com/data");
            should.not.exist(result.error);
        });
    });

    describe("Invalid redirects - open redirect attacks", () => {
        it("should block protocol-relative URLs (//evil.com)", () => {
            const result = validateRedirectUrl("//evil.com/phishing", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/not allowed|not permitted/i);
        });

        it("should block redirects to non-whitelisted domains", () => {
            const result = validateRedirectUrl("http://evil.com/phishing", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/not allowed|not permitted/i);
        });

        it("should block https redirects to unauthorized domains", () => {
            const result = validateRedirectUrl("https://attacker.com/steal-data", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/not allowed|not permitted/i);
        });

        it("should block data URLs", () => {
            const result = validateRedirectUrl("data:text/html,<script>alert('xss')</script>", testAllowedDomains);
            result.isValid.should.be.false();
        });

        it("should block javascript URLs", () => {
            const result = validateRedirectUrl("javascript:alert('xss')", testAllowedDomains);
            result.isValid.should.be.false();
        });

        it("should block file protocol URLs", () => {
            const result = validateRedirectUrl("file:///etc/passwd", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/not allowed|not permitted/i);
        });

        it("should block FTP URLs", () => {
            const result = validateRedirectUrl("ftp://evil.com/malware", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/not allowed|not permitted/i);
        });

        it("should block URLs with encoded protocols", () => {
            const result = validateRedirectUrl("ht%74p://evil.com", testAllowedDomains);
            result.isValid.should.be.false();
        });
    });

    describe("Invalid redirects - malformed input", () => {
        it("should reject null URL", () => {
            const result = validateRedirectUrl(null, testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/required|string/i);
        });

        it("should reject undefined URL", () => {
            const result = validateRedirectUrl(undefined, testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/required|string/i);
        });

        it("should reject empty string", () => {
            const result = validateRedirectUrl("", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/empty|required/i);
        });

        it("should reject whitespace-only string", () => {
            const result = validateRedirectUrl("   ", testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/empty|required/i);
        });

        it("should reject non-string input", () => {
            const result = validateRedirectUrl(123, testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/string/i);
        });

        it("should reject object input", () => {
            const result = validateRedirectUrl({url: "/test"}, testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/string/i);
        });

        it("should reject array input", () => {
            const result = validateRedirectUrl(["/test"], testAllowedDomains);
            result.isValid.should.be.false();
            result.error.should.match(/string/i);
        });
    });

    describe("Edge cases and special characters", () => {
        it("should handle URLs with whitespace by trimming them", () => {
            const result = validateRedirectUrl("  /dashboard  ", testAllowedDomains);
            result.isValid.should.be.true();
            result.url.should.equal("/dashboard");
        });

        it("should handle URLs with encoded characters", () => {
            const result = validateRedirectUrl("/search?q=%20test%20", testAllowedDomains);
            result.isValid.should.be.true();
        });

        it("should handle URLs with special characters in path", () => {
            const result = validateRedirectUrl("/user/john.doe", testAllowedDomains);
            result.isValid.should.be.true();
        });

        it("should handle URLs with port numbers (whitelisted domain)", () => {
            const result = validateRedirectUrl("http://example.com:8080/path", testAllowedDomains);
            result.isValid.should.be.true();
        });

        it("should handle URLs with port numbers (non-whitelisted domain)", () => {
            const result = validateRedirectUrl("http://evil.com:8080/path", testAllowedDomains);
            result.isValid.should.be.false();
        });

        it("should handle URLs with basic auth (whitelisted domain)", () => {
            const result = validateRedirectUrl("http://user:pass@example.com/path", testAllowedDomains);
            result.isValid.should.be.true();
        });

        it("should handle URLs with basic auth (non-whitelisted domain)", () => {
            const result = validateRedirectUrl("http://user:pass@evil.com/path", testAllowedDomains);
            result.isValid.should.be.false();
        });
    });

    describe("Default allowed domains", () => {
        it("should use default domains when not provided", () => {
            const result = validateRedirectUrl("/dashboard");
            result.isValid.should.be.true();
        });

        it("should block non-whitelisted external URLs with defaults", () => {
            const result = validateRedirectUrl("http://attacker.com");
            result.isValid.should.be.false();
        });
    });
});

describe("URL Validator - safeRedirect middleware", () => {
    it("should redirect when URL is valid", (done) => {
        const mockRes = {
            redirect: (url) => {
                url.should.equal("/dashboard");
                done();
            }
        };

        safeRedirect(mockRes, "/dashboard");
    });

    it("should return 400 when URL is invalid", (done) => {
        const mockRes = {
            status: (code) => {
                code.should.equal(400);
                return {
                    send: (data) => {
                        data.error.should.equal("Invalid redirect URL");
                        done();
                    }
                };
            }
        };

        safeRedirect(mockRes, "//evil.com");
    });

    it("should call logger when redirect is blocked", (done) => {
        let logged = false;
        const mockLogger = () => {
            logged = true;
        };

        const mockRes = {
            status: () => ({
                send: () => {
                    logged.should.be.true();
                    done();
                }
            })
        };

        safeRedirect(mockRes, "http://evil.com", mockLogger);
    });
});
