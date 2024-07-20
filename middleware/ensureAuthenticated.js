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
    return res.status(401).json({ message: "Token is not valid" });
  }
};

module.exports = ensureAuthenticated;
