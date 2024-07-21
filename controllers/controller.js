const {
  User,
  UserRefreshTokens,
  UserInvalidTokens,
} = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticator } = require("otplib");
const qrcode = require("qrcode");
const crypto = require("crypto");
const NodeCache = require("node-cache");

const config = require("../config");
const cache = new NodeCache();

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
      twoFactorEnabled: false,
      twoFactorSecret: null,
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

    // if user has 2FA enabled
    if (user.twoFactorEnabled) {
      const tempToken = crypto.randomUUID();

      cache.set(
        config.cacheTemporaryTokenPrefix + tempToken,
        user._id,
        config.cacheTemporaryExpiresInSeconds
      );

      return res.status(200).json({
        tempToken,
        expiresInSeconds: config.cacheTemporaryExpiresInSeconds,
      });
    } else {
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
    }

    // // Generate access token
    // const accessToken = jwt.sign(
    //   { userId: user._id },
    //   config.accessTokenSecret,
    //   { subject: "accessApi", expiresIn: config.accessTokenExpires }
    // );

    // // Generate refresh token
    // const refreshToken = jwt.sign(
    //   { userId: user._id },
    //   config.refreshTokenSecret,
    //   { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    // );

    // // Store refresh token in database
    // await UserRefreshTokens.insert({
    //   refreshToken: refreshToken,
    //   userId: user._id,
    // });

    // // Return user info and tokens
    // return res.status(200).json({
    //   id: user._id,
    //   name: user.name,
    //   email: user.email,
    //   accessToken: accessToken,
    //   refreshToken: refreshToken,
    // });
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

// // 2 FA
// module.exports.twoFactor = async (req, res) => {
//   try {
//     const user = await User.findOne({ _id: req.user.id });

//     const secret = authenticator.generateSecret();
//     const uri = authenticator.keyuri(user.email, "company_name", secret);

//     await User.update({ _id: req.user.id }, { $set: { "2faSecret": secret } });
//     await User.compactDatafile();

//     const qrCode = await qrcode.toBuffer(uri, { type: "image/png", margin: 1 });
//     res.setHeader("Content-Disposition", "attachment: filename=qrcode.png");
//     return res.status(200).type("image/png").send(qrCode);
//   } catch (error) {
//     return res.status(500).json({ message: error.message });
//   }
// };

// set up 2fa
module.exports.setupTwoFactor = async (req, res) => {
  try {
    const user = await User.findOne({ _id: req.user.id });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(user.email, "YourCompanyName", secret);

    // Store the secret temporarily
    await User.update(
      { _id: req.user.id },
      { $set: { tempTwoFactorSecret: secret } }
    );
    await User.compactDatafile();

    const qrCode = await qrcode.toBuffer(uri, { type: "image/png", margin: 1 });
    res.setHeader("Content-Disposition", "attachment; filename=qrcode.png");
    return res.status(200).type("image/png").send(qrCode);
  } catch (error) {
    console.error("Error in setupTwoFactor:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// enable 2fa
module.exports.enableTwoFactor = async (req, res) => {
  try {
    const { token } = req.body;
    const user = await User.findOne({ _id: req.user.id });

    if (!user || !user.tempTwoFactorSecret) {
      return res.status(400).json({ message: "2FA setup not initiated" });
    }

    const isValid = authenticator.verify({
      token,
      secret: user.tempTwoFactorSecret,
    });

    if (isValid) {
      await User.update(
        { _id: req.user.id },
        {
          $set: { twoFactorSecret: user.tempTwoFactorSecret },
          $unset: { tempTwoFactorSecret: "" },
        }
      );
      await User.compactDatafile();
      return res.status(200).json({ message: "2FA enabled successfully" });
    } else {
      return res.status(400).json({ message: "Invalid token" });
    }
  } catch (error) {
    console.error("Error in enableTwoFactor:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

module.exports.login2fa = async (req, res) => {
  try {
    const { tempToken, token } = req.body;

    if (!tempToken || !token) {
      return res
        .status(422)
        .json({ message: "Please fill in all fields (tempToken and token)" });
    }

    const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);

    if (!userId) {
      return res.status(401).json({
        message: "The provided temporary token is incorrect or expired",
      });
    }

    const user = await User.findOne({ _id: userId });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const verified = authenticator.check(token, user.twoFactorSecret);

    if (!verified) {
      return res
        .status(401)
        .json({ message: "The provided token is incorrect or expired" });
    }

    // Remove temporary token from cache
    cache.del(config.cacheTemporaryTokenPrefix + tempToken);

    const accessToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: config.accessTokenExpires }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      config.refreshTokenSecret,
      { subject: "refreshToken", expiresIn: config.refreshTokenExpiresIn }
    );

    await UserRefreshTokens.insert({
      refreshToken,
      userId: user._id,
    });

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken,
      refreshToken,
    });
  } catch (error) {
    console.error("Error in login2fa:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};
