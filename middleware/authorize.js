// const jwt = require("jsonwebtoken");
// const config = require("../config");
const User = require("../models/user");

function authorize(roles = []) {
  return async function (req, res, next) {
    const user = await User.findOne({ _id: req.user.id });

    if (!user || !roles.includes(user.role)) {
      return res.status(403).json({ message: "Access denied" });
    }
    next();
  };
}

module.exports = authorize;
