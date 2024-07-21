const {
  User,
  UserRefreshTokens,
  UserInvalidTokens,
} = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const config = require("../config");

module.exports.stay = async (req, res) => {
  res.send("auth auth");
};
// register user
module.exports.register = async (req, res) => {
  try {
    const { name, email, password, role } = req.body; //if client doesnt send "role" field, asumme its a member user not admin
    if (!name || !email || !password) {
      return res.status(422).json({ message: "please fill in all fields" }); //Unprocessable Entity
    }

    if (await User.findOne({ email })) {
      return res.status(409).json({ message: "Email already exists" }); //Status Code: Conflict
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user in database
    const newUser = await User.insert({
      name,
      email,
      password: hashedPassword,
      role: role ?? "member",
    });

    return res
      .status(201) //created
      .json({ message: "user registered successfully", id: newUser._id });
  } catch (error) {
    return res.status(500).json({ message: error.message }); //Internal Server Error
  }
};

// user login
module.exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(422).json({ message: "please fill in all fields" });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "invalid email, password" }); //unauthorized
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "invalid email, password" });
    }

    // Generate access token
    const accessToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: config.accessTokenExpires }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { userId: user._id },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    );

    // Store refresh token in database
    await UserRefreshTokens.insert({
      refreshToken: refreshToken,
      userId: user._id,
    });

    // Return user info and tokens
    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken: accessToken,
      refreshToken: refreshToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message }); //Internal Server Error
  }
};

// refresh token route
module.exports.refreshtoken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(401).json({ message: "refresh token not found" });
    }

    // Verify refresh token
    const decodedRefreshToken = jwt.verify(
      refreshToken,
      config.refreshTokenSecret
    );

    // Check if refresh token exists in database
    const userRefreshToken = await UserRefreshTokens.findOne({
      refreshToken: refreshToken,
      userId: decodedRefreshToken.userId,
    });
    if (!userRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refrfesh token invalid or expired" });
    }

    // Remove old refresh token
    await UserRefreshTokens.remove({ _id: userRefreshToken._id });
    await UserRefreshTokens.compactDatafile();

    // Generate new access token
    const accessToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: config.accessTokenExpires }
    );

    // Generate new refresh token
    const newRefreshToken = jwt.sign(
      { userId: decodedRefreshToken.userId },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    );

    // Store new refresh token in database
    await UserRefreshTokens.insert({
      refreshToken: newRefreshToken,
      userId: decodedRefreshToken.userId,
    });

    // Return new tokens
    return res.status(200).json({
      accessToken: accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    if (
      error instanceof jwt.TokenExpiredError ||
      error instanceof jwt.JsonWebTokenError
    ) {
      return res
        .status(401)
        .json({ message: "Refrfesh token invalid or expired" });
    }
    return res.status(500).json({ message: error.message });
  }
};

//logout
module.exports.logout = async (req, res) => {
  try {
    // Remove all refresh tokens for the user
    await UserRefreshTokens.removeMany({ userId: req.user.id });
    await UserRefreshTokens.compactDatafile();

    // Add current access token to invalid tokens list
    await UserInvalidTokens.insert({
      token: req.token.value,
      userId: req.user.id,
      expirationTime: req.token.exp,
    });

    // Return success response
    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

// only for auth user
module.exports.loggedin = async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.user.id });
    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

// admins
module.exports.admin = async (req, res) => {
  return res
    .status(200)
    .json({ message: "only admins can access this route. welcome" });
};

// moderator and admin
module.exports.moderators = async (req, res) => {
  return res.status(200).json({
    message: "only admins and moderators can access this route. welcome",
  });
};
