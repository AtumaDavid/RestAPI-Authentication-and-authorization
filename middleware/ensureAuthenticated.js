const jwt = require("jsonwebtoken");
const config = require("../config");
const { UserInvalidTokens } = require("../models/user");

// Middleware function to ensure user is authenticated
const ensureAuthenticated = async (req, res, next) => {
  // Extract token from request headers
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  // Check if the token is in the invalid tokens list
  if (await UserInvalidTokens.findOne({ token: token })) {
    return res
      .status(401)
      .json({ message: "Access token invalid", code: "AccessTokenInvalid" });
  }

  try {
    // Verify the token
    const decoded = jwt.verify(token, config.accessTokenSecret);

    // Attach token and user info to the request object
    req.token = { value: token, exp: decoded.exp };
    req.user = { id: decoded.userId };

    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res
        .status(401)
        .json({ message: "access token expired", code: "accesTokenExpired" });
    } else if (err instanceof jwt.JsonWebTokenError) {
      return res
        .status(401)
        .json({ message: "access token invalid", code: "AccessTokenInvalid" });
    } else {
      return res.status(401).json({ message: "Token is invalid" });
    }
    // return res.status(401).json({ message: "Token is not valid" });
  }
};

module.exports = ensureAuthenticated;
