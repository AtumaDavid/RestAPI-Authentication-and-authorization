const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const config = require("../config");

module.exports.stay = async (req, res) => {
  res.send("auth auth");
};
// register user
module.exports.register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(422).json({ message: "please fill in all fields" }); //Unprocessable Entity
    }

    if (await User.findOne({ email })) {
      return res.status(409).json({ message: "Email already exists" }); //Status Code: Conflict
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.insert({
      name,
      email,
      password: hashedPassword,
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

    const accessToken = jwt.sign(
      { userId: user._id },
      config.accessTokenSecret,
      { subject: "accessApi", expiresIn: "1h" }
    );

    return res.status(200).json({
      id: user._id,
      name: user.name,
      email: user.email,
      accessToken: accessToken,
    });
  } catch (error) {
    return res.status(500).json({ message: error.message }); //Internal Server Error
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
