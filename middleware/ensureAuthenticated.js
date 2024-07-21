const jwt = require("jsonwebtoken");
const config = require("../config");

const ensureAuthenticated = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "No token, authorization denied" });
  }

  try {
    const decoded = jwt.verify(token, config.accessTokenSecret);
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
