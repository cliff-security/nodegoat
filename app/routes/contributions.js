const ContributionsDAO = require("../data/contributions-dao").ContributionsDAO;
const {
    environmentalScripts
} = require("../../config/config");

/* Validation helper to safely parse and validate contribution input */
function validateContributionInput(value) {
    // Validate input is a string or number
    if (value === null || value === undefined) {
        return { valid: false, error: "Value is required" };
    }
    
    // Parse as integer - safely rejects any non-numeric strings
    const parsed = parseInt(value, 10);
    
    // Check for NaN result (invalid conversion)
    if (isNaN(parsed)) {
        return { valid: false, error: "Value must be a valid number" };
    }
    
    // Check for negative values
    if (parsed < 0) {
        return { valid: false, error: "Value cannot be negative" };
    }
    
    return { valid: true, value: parsed };
}

/* The ContributionsHandler must be constructed with a connected db */
function ContributionsHandler(db) {
    "use strict";

    const contributionsDAO = new ContributionsDAO(db);

    this.displayContributions = (req, res, next) => {
        const {
            userId
        } = req.session;

        contributionsDAO.getByUserId(userId, (error, contrib) => {
            if (error) return next(error);

            contrib.userId = userId; //set for nav menu items
            return res.render("contributions", {
                ...contrib,
                environmentalScripts
            });
        });
    };

    this.handleContributionsUpdate = (req, res, next) => {

        // Security fix for RCE vulnerability (CVE-style): Replaced eval() with safe parseInt()
        // and added strict input validation to prevent code injection attacks
        const preTaxValidation = validateContributionInput(req.body.preTax);
        const afterTaxValidation = validateContributionInput(req.body.afterTax);
        const rothValidation = validateContributionInput(req.body.roth);
        
        const {
            userId
        } = req.session;

        // Check for validation errors
        if (!preTaxValidation.valid || !afterTaxValidation.valid || !rothValidation.valid) {
            return res.render("contributions", {
                updateError: "Invalid contribution percentages",
                userId,
                environmentalScripts
            });
        }

        const preTax = preTaxValidation.value;
        const afterTax = afterTaxValidation.value;
        const roth = rothValidation.value;

        // Validate total contributions do not exceed 30%
        const totalContributions = preTax + afterTax + roth;
        if (totalContributions > 30) {
            return res.render("contributions", {
                updateError: "Contribution percentages cannot exceed 30 %",
                userId,
                environmentalScripts
            });
        }

        contributionsDAO.update(userId, preTax, afterTax, roth, (err, contributions) => {

            if (err) return next(err);

            contributions.updateSuccess = true;
            return res.render("contributions", {
                ...contributions,
                environmentalScripts
            });
        });

    };

}

module.exports = ContributionsHandler;
