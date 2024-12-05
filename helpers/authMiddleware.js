const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authMiddleware = (requiredRoles) => {
    return async (req, res, next) => {
        try {
            const token = req.headers.authorization?.split(" ")[1];

            if (!token) {
                return res.status(401).json({
                    success: false,
                    message: 'Authorization token is missing'
                });
            }

            // Verify the token using the common secret key
            let decoded;
            try {
                decoded = jwt.verify(token, process.env.ADMINSAULTKEY);
            } catch (adminError) {
                try {
                    decoded = jwt.verify(token, process.env.USERSAULTKEY);
                } catch (userError) {
                    throw new Error("Invalid token");
                }
            }
            // Use one shared secret key
            const userId = decoded.id;

            // Fetch the user from the database
            const user = await User.findById(userId);
            if (!user) {
                return res.status(401).json({
                    success: false,
                    message: "User not found"
                });
            }

            // Check if the user's role is included in the required roles
            if (requiredRoles && !requiredRoles.includes(user.role)) {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden: You do not have access to this resource",
                });
            }

            // Attach user and token to the request
            req.user = user;
            req.token = token;

            next();
        } catch (error) {
            console.error(error);
            if (error.name === "TokenExpiredError") {
                return res.status(401).json({
                    success: false,
                    message: "Session expired, Please login again"
                });
            } else if (error.name === "JsonWebTokenError") {
                return res.status(401).json({
                    success: false,
                    message: "Invalid token, please login again"
                });
            }

            res.status(500).json({
                success: false,
                message: "Internal server error"
            });
        }
    };
};

module.exports = authMiddleware;
